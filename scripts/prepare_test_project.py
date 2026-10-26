from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


def prepare(installation: Path, output: Path, timeout: int) -> Path:
    repository = Path(__file__).resolve().parent.parent
    projects = output / "projects"
    projects.mkdir()
    runtime = output / "runtime"
    runtime.mkdir()
    subprocess.run([sys.executable, str(repository / "tests/fixtures/build.py"), str(output)], check=True)
    launch_options = []
    for line in (installation / "support/launch.properties").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"VMARGS", "VMARGS_LINUX"}:
            launch_options.append(value)
    command = [
        "java", *launch_options, "-Xmx2G", "-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2",
        "-Djava.awt.headless=true",
        f"-Dapplication.settingsdir={runtime / 'settings'}",
        f"-Dapplication.cachedir={runtime / 'cache'}",
        f"-Dapplication.tempdir={runtime / 'tmp'}",
        "-cp", str(installation / "Ghidra/Framework/Utility/lib/Utility.jar"),
        "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless",
        str(projects), "FixtureProject", "-import", str(output / "binaries"),
        "-recursive", "-analysisTimeoutPerFile", "120", "-max-cpu", "2",
        "-log", str(output / "import.log"), "-scriptlog", str(output / "scripts.log"),
    ]
    console = output / "console.log"
    print(f"Importing and analyzing nine fixture libraries: {console}", flush=True)
    with console.open("w") as stream:
        try:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise SystemExit(f"Fixture import timed out; see {console}") from None
    transcript = console.read_text()
    paths = [f"/binaries/fixture_{index:02d}/libfixture.so" for index in range(1, 10)]
    complete = (
        result.returncode == 0
        and transcript.count("REPORT: Import succeeded") == len(paths)
        and transcript.count("REPORT: Analysis succeeded for file:") == len(paths)
        and all(f"REPORT: Save succeeded for: {path} " in transcript for path in paths)
    )
    if not complete:
        print(transcript[-6000:], file=sys.stderr)
        raise SystemExit(f"Fixture project was not completely imported and analyzed; see {console}")
    project = projects / "FixtureProject.gpr"
    if not project.is_file():
        raise SystemExit(f"Ghidra did not create {project}")
    (output / "fixture.json").write_text(json.dumps({
        "ghidra_version": "12.2", "project": str(project), "programs": paths,
        "binaries": str(output / "binaries"), "log": str(console),
    }, indent=2) + "\n")
    return project


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and analyze an isolated nine-library Ghidra 12.2 fixture project")
    parser.add_argument("--ghidra-home", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    parser.add_argument("--output-dir", type=Path, help="New directory; existing paths are never overwritten")
    parser.add_argument("--timeout", type=int, default=600, help="Maximum seconds for Ghidra import and analysis")
    args = parser.parse_args()
    if not args.ghidra_home:
        parser.error("set GHIDRA_INSTALL_DIR or pass --ghidra-home")
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        parser.error("the ELF/x86-64 integration fixtures require Linux x86-64")
    if not shutil.which("gcc") or not shutil.which("java"):
        parser.error("gcc and JDK 25 java must be available on PATH")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    installation = Path(args.ghidra_home).resolve()
    properties = installation / "Ghidra/application.properties"
    if not properties.is_file():
        parser.error(f"not a Ghidra installation: {installation}")
    values = dict(line.split("=", 1) for line in properties.read_text().splitlines() if "=" in line and not line.startswith("#"))
    if values.get("application.version") != "12.2":
        parser.error("these integration fixtures target Ghidra 12.2")
    if args.output_dir:
        output = args.output_dir.resolve()
        if output.exists():
            parser.error(f"refusing to overwrite existing output directory: {output}")
        output.mkdir(parents=True)
    else:
        output = Path(tempfile.mkdtemp(prefix="ghidramcp-fixtures-"))
    print(f"Fixture artifacts: {output}", flush=True)
    print(prepare(installation, output, args.timeout), flush=True)


if __name__ == "__main__":
    main()
