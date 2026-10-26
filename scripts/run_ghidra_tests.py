from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def compile_sources(installation: Path, output: Path) -> str:
    repository = Path(__file__).resolve().parent.parent
    jars = sorted((installation / "Ghidra").glob("**/lib/*.jar"))
    if not jars:
        raise ValueError(f"No Ghidra libraries found in {installation}")
    output.mkdir(parents=True, exist_ok=True)
    classpath = os.pathsep.join(map(str, jars))
    sources = sorted((repository / "src/main/java").rglob("*.java"))
    sources += sorted((repository / "tests/ghidra").glob("*.java"))
    subprocess.run([
        "javac", "-proc:none", "--release", "25", "-cp", classpath,
        "-d", str(output), *map(str, sources),
    ], check=True)
    return os.pathsep.join([str(output), classpath])


def copy_project(project: Path, destination: Path) -> Path:
    project = project.resolve()
    if project.suffix != ".gpr":
        project = project.with_name(project.name + ".gpr")
    repository = project.with_suffix(".rep")
    if not project.is_file() or not repository.is_dir():
        raise ValueError(f"Expected an existing Ghidra .gpr project: {project}")
    if any(project.parent.glob(project.stem + ".lock*")):
        raise ValueError(f"Close the fixture project before copying it: {project}")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(project, destination / project.name)
    shutil.copytree(repository, destination / repository.name)
    return destination / project.name


def java_command(installation: Path, classpath: str, project: Path,
                 script: str, script_args: list[str], runtime: Path) -> list[str]:
    runtime.mkdir(parents=True, exist_ok=True)
    gui = script == "GuiSmokeRunner"
    return [
        "java", f"-Djava.awt.headless={str(not gui).lower()}",
        f"-Dapplication.settingsdir={runtime / 'settings'}",
        f"-Dapplication.cachedir={runtime / 'cache'}",
        f"-Dapplication.tempdir={runtime / 'tmp'}",
        "--enable-native-access=ALL-UNNAMED", "-cp", classpath,
        "GuiSmokeRunner" if gui else "StandaloneSmokeRunner", str(installation), str(project.parent),
        project.stem, *([] if gui else [script]), *script_args,
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run smoke tests in the installed Ghidra 12.2 runtime")
    parser.add_argument("--ghidra-home", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    parser.add_argument("--project", type=Path, required=True, help="Closed, imported nine-library fixture .gpr project")
    parser.add_argument("--smoke", nargs="+", default=["ResearchSmoke", "MutationSmoke", "AnalysisSmoke", "ProjectSmoke"])
    parser.add_argument("--script-arg", action="append", default=[])
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--timeout", type=int, default=600, help="Maximum seconds per smoke test")
    args = parser.parse_args()
    if not args.ghidra_home:
        parser.error("set GHIDRA_INSTALL_DIR or pass --ghidra-home")
    installation = Path(args.ghidra_home).resolve()
    output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="ghidramcp-tests-"))
    output.mkdir(parents=True, exist_ok=True)
    print(f"Test artifacts: {output}", flush=True)
    classpath = compile_sources(installation, output / "classes")
    results = []
    for smoke in args.smoke:
        run = output / smoke
        project = copy_project(args.project, run / "projects")
        script_args = args.script_arg
        if smoke == "ResearchSmoke" and not script_args:
            script_args = [str(run / "report.json")]
        command = java_command(installation, classpath, project, smoke, script_args, run / "runtime")
        log = run / "console.log"
        print(f"Running {smoke}: {log}", flush=True)
        with log.open("w") as stream:
            try:
                completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=args.timeout)
                code = completed.returncode
            except subprocess.TimeoutExpired:
                code = 124
        if smoke == "GuiSmokeRunner" and code == 0 and "GUI_SMOKE_OK" not in log.read_text():
            code = 1
        results.append({"smoke": smoke, "status": "passed" if code == 0 else "failed", "exit_code": code, "log": str(log)})
        print(f"{smoke}: {results[-1]['status']}", flush=True)
        if code:
            print(log.read_text()[-6000:])
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    raise SystemExit(any(result["exit_code"] for result in results))


if __name__ == "__main__":
    main()
