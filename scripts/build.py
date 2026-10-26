import argparse
import os
from pathlib import Path
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the Ghidra 12.2 extension")
    parser.add_argument("--ghidra-home", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    parser.add_argument("--maven-repo")
    args = parser.parse_args()
    if not args.ghidra_home:
        parser.error("set GHIDRA_INSTALL_DIR or pass --ghidra-home")
    installation = Path(args.ghidra_home).resolve()
    properties = installation / "Ghidra" / "application.properties"
    if not properties.is_file():
        parser.error(f"not a Ghidra installation: {installation}")
    values = dict(line.split("=", 1) for line in properties.read_text().splitlines() if "=" in line and not line.startswith("#"))
    if values.get("application.version") != "12.2":
        parser.error("this extension targets Ghidra 12.2")
    command = ["mvn", "--batch-mode", f"-Dghidra.install.dir={installation}"]
    if args.maven_repo:
        command.append(f"-Dmaven.repo.local={Path(args.maven_repo).resolve()}")
    command.extend(["clean", "verify"])
    raise SystemExit(subprocess.call(command, cwd=Path(__file__).resolve().parent.parent))


if __name__ == "__main__":
    main()
