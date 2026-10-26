import argparse
import hashlib
import io
from pathlib import Path
import zipfile


def main() -> None:
    repository = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Package the Ghidra 12.2 extension and MCP bridge")
    parser.add_argument("--output-dir", type=Path, default=repository / "target")
    args = parser.parse_args()
    extension = repository / "target/GhidraMCP-12.2.zip"
    if not extension.is_file():
        parser.error("build target/GhidraMCP-12.2.zip with scripts/build.py first")
    catalog = repository / "protocol/tools.json"
    with zipfile.ZipFile(extension) as archive:
        properties = archive.read("GhidraMCP/extension.properties").decode()
        if "version=12.2" not in properties.splitlines():
            parser.error("the extension must target Ghidra 12.2")
        with zipfile.ZipFile(io.BytesIO(archive.read("GhidraMCP/lib/GhidraMCP.jar"))) as jar:
            if jar.read("mcp/tools.json") != catalog.read_bytes():
                parser.error("the extension tool catalog is stale; rebuild before packaging")
    files = [(extension, extension.name), (repository / "docs/INSTALL.md", "INSTALL.md")]
    files += [(repository / name, name) for name in (
        "bridge_mcp_ghidra.py", "requirements.txt", "requirements.lock", "LICENSE", "NOTICE",
    )]
    files += [(path, path.relative_to(repository).as_posix())
              for path in sorted((repository / "ghidra_mcp").glob("*.py"))]
    files.append((catalog, "protocol/tools.json"))
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    package = output / "GhidraMCP-12.2-release.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, name in files:
            archive.write(path, name)
    checksum = hashlib.sha256(package.read_bytes()).hexdigest()
    package.with_suffix(".zip.sha256").write_text(f"{checksum}  {package.name}\n", encoding="utf-8")
    print(package)
    print(f"SHA-256: {checksum}")


if __name__ == "__main__":
    main()
