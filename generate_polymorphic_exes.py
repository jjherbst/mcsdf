#!/usr/bin/env python
"""
build_poly.py

Generate N polymorphic, *benign* executables that each contain the
EICAR test signature XOR-encrypted with a random key.
Every variant writes the same checksum.csv at runtime.

Usage (inside a Python 3.10/3.11 venv):
    python build_poly.py           # builds 10 variants
    python build_poly.py -n 3      # builds 3 variants
"""

import argparse
import base64
import pathlib
import secrets
import subprocess
import sys
import textwrap

# 68-byte EICAR signature on a single line
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# Source template for each polymorphic variant
TEMPLATE = r'''
# -*- coding: utf-8 -*-
import base64, csv, hashlib

blob = "{blob}"
key  = {key}

eicar = bytes(b ^ key for b in base64.b64decode(blob))  # decrypt in RAM

sha = hashlib.sha256(b"benign").hexdigest()
with open("checksum.csv", "w", newline="") as f:
    csv.writer(f).writerow(["payload", sha])
print("Wrote checksum", sha)
'''


def build_variant(idx: int, paths: dict) -> None:
    """Generate, compile, and store a single variant."""
    key = secrets.randbelow(256)
    b64 = base64.b64encode(bytes(b ^ key for b in EICAR)).decode("ascii")
    code = TEMPLATE.format(blob=b64, key=key)

    src_file = paths["src"] / f"poly_{idx}.py"
    src_file.write_text(textwrap.dedent(code), encoding="utf-8")

    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--onefile",
        "--noconfirm",
        "--log-level=INFO",
        f"--distpath={paths['dist']}",
        f"--workpath={paths['build'] / f'build_{idx}'}",
        f"--specpath={paths['spec']}",
        src_file,
    ]

    print(f"[*] Building poly_{idx}.exe …")
    subprocess.run(cmd, check=True)
    print(f"[+] Finished poly_{idx}.exe")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate polymorphic benign EICAR executables"
    )
    parser.add_argument(
        "-n",
        "--num",
        type=int,
        default=10,
        help="Number of variants to build (default: 10)",
    )
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().with_suffix("")
    paths = {
        "src": root / "variants" / "src",
        "dist": root / "variants" / "dist",
        "spec": root / "variants" / "spec",
        "build": root,
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)

    for i in range(args.num):
        build_variant(i, paths)

    print("\nAll variants saved to:", paths["dist"])


if __name__ == "__main__":
    main()
