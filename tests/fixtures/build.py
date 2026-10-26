from __future__ import annotations

import argparse
from pathlib import Path
import subprocess


def build(output: Path) -> None:
    source_dir = output / "sources"
    binary_dir = output / "binaries"
    source_dir.mkdir(parents=True, exist_ok=True)
    binary_dir.mkdir(parents=True, exist_ok=True)
    for index in range(1, 10):
        directory = binary_dir / f"fixture_{index:02d}"
        directory.mkdir(exist_ok=True)
        source = source_dir / f"fixture_{index:02d}.c"
        if index == 2:
            body = (
                "extern int shared_helper(int value);\n"
                "int fixture_entry(int value) { return shared_helper(value) + 1002; }\n"
            )
        else:
            body = f"int fixture_entry(int value) {{ return value * {index} + {1000 + index}; }}\n"
        if index == 1:
            body += "int shared_helper(int value) { return value * 5 + 31; }\n"
        body += (
            "int (*fixture_pointer)(int) = fixture_entry;\n"
            f"const unsigned char fixture_bytes[] = {{ {index}, 17, 34, 51 }};\n"
            f'const char fixture_message[] = "fixture-{index:02d}";\n'
            "unsigned char fixture_bss[64];\n"
        )
        source.write_text(body)
        command = [
            "gcc", "-shared", "-fPIC", "-O1", "-g0",
            f"-Wl,-soname,libfixture_{index:02d}.so",
            "-o", str(directory / "libfixture.so"), str(source),
        ]
        if index == 2:
            command += [f"-L{binary_dir / 'fixture_01'}", "-Wl,--no-as-needed", "-l:libfixture.so"]
        subprocess.run(command, check=True)
    print(binary_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    build(parser.parse_args().output.resolve())
