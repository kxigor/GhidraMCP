import argparse
import hashlib
from pathlib import Path
import urllib.request
import zipfile


VERSION = "12.2"
ARCHIVE = "ghidra_12.2_PUBLIC_20261016.zip"
SHA256 = "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
URL = f"https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_{VERSION}_build/{ARCHIVE}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Download the verified official Ghidra 12.2 distribution")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / ARCHIVE
    if not archive.exists():
        partial = archive.with_suffix(".part")
        request = urllib.request.Request(URL, headers={"User-Agent": "GhidraMCP-build"})
        with urllib.request.urlopen(request, timeout=60) as source, partial.open("wb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
        partial.rename(archive)
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != SHA256:
        raise SystemExit(f"SHA-256 mismatch for {archive}")
    installation = destination / f"ghidra_{VERSION}_PUBLIC"
    if installation.exists():
        raise SystemExit(f"Verified archive is available; refusing to overwrite existing installation: {installation}")
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            if not (destination / member.filename).resolve().is_relative_to(destination):
                raise SystemExit("Invalid path inside distribution archive")
        bundle.extractall(destination)
        for member in bundle.infolist():
            mode = (member.external_attr >> 16) & 0o777
            if mode:
                (destination / member.filename).chmod(mode)
    print(installation)


if __name__ == "__main__":
    main()
