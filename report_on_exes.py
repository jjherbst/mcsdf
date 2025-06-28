#!/usr/bin/env python3
"""
scan_and_report.py

Scans the 'variants/executables' directory and enriches the existing
eicar_variants_report.csv with additional AV-relevant and forensic metadata:

- filename
- sha256
- file_size
- creation_time (UTC)
- entropy (Shannon)
- section_count (PE)
- import_count (PE)
- num_strings (printable ASCII ≥4 chars)
- longest_string (length of the longest ASCII string)
- contains_eicar (True/False)
- hostname (machine name)
- os_platform (OS and version)
- scan_timestamp (UTC)

Usage:
    python scan_and_report.py [--base-dir PATH]

Dependencies:
    pip install pefile entropy
"""

import argparse
import base64
import csv
import hashlib
import re
import socket
import platform
from datetime import datetime
from pathlib import Path

# Attempt to import pefile; handle if missing
try:
    import pefile
except ImportError:
    pefile = None

# Attempt to import entropy library for Shannon entropy
try:
    from entropy import shannon_entropy
except ImportError:
    import math
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        ent = 0.0
        length = len(data)
        for c in counts.values():
            p = c / length
            ent -= p * math.log2(p)
        return ent

# EICAR signature for detection
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def analyze_file(path: Path) -> dict:
    data = path.read_bytes()
    # Basic attributes
    sha256 = hashlib.sha256(data).hexdigest()
    file_size = path.stat().st_size
    creation_time = datetime.utcfromtimestamp(path.stat().st_ctime).isoformat() + "Z"
    entropy = round(shannon_entropy(data), 4)
    # PE analysis
    if pefile:
        try:
            pe = pefile.PE(str(path), fast_load=True)
            section_count = len(pe.sections)
            import_count = sum(len(entry.imports) for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))
            pe.close()
        except Exception:
            section_count = ""
            import_count = ""
    else:
        section_count = ""
        import_count = ""
    # Strings analysis
    strings = re.findall(br"[\x20-\x7E]{4,}", data)
    num_strings = len(strings)
    longest_string = max((len(s) for s in strings), default=0)
    # EICAR detection
    contains_eicar = EICAR_SIGNATURE in data
    return {
        "filename": path.name,
        "sha256": sha256,
        "file_size": file_size,
        "creation_time": creation_time,
        "entropy": entropy,
        "section_count": section_count,
        "import_count": import_count,
        "num_strings": num_strings,
        "longest_string": longest_string,
        "contains_eicar": contains_eicar
    }

def scan_variants(base_dir: Path):
    variants_dir = base_dir / "variants"
    exe_dir = variants_dir / "executables"
    report_in = variants_dir / "eicar_variants_report.csv"
    report_out = variants_dir / "eicar_variants_full_report.csv"

    # Load existing report
    if not report_in.exists():
        print(f"[ERROR] Input report not found: {report_in}")
        return

    rows = []
    with report_in.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    # Prepare output CSV
    fieldnames = list(reader.fieldnames) + [
        "creation_time","entropy","section_count","import_count",
        "num_strings","longest_string","contains_eicar",
        "hostname","os_platform","scan_timestamp"
    ]
    report_out.parent.mkdir(parents=True, exist_ok=True)
    with report_out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        hostname = socket.gethostname()
        os_platform = platform.system() + " " + platform.release()
        scan_ts = datetime.utcnow().isoformat() + "Z"
        for row in rows:
            filename = row.get("filename")
            exe_path = exe_dir / filename
            if not exe_path.exists():
                print(f"[WARNING] File not found: {exe_path}")
                continue
            attrs = analyze_file(exe_path)
            combined = {**row, **attrs,
                        "hostname": hostname,
                        "os_platform": os_platform,
                        "scan_timestamp": scan_ts}
            writer.writerow(combined)
            print(f"[+] Scanned: {filename}")

    print(f"Full report written to: {report_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan directory and generate enriched report")
    parser.add_argument("--base-dir", type=Path, default=Path.cwd(),
                        help="Base directory containing 'variants/'")
    args = parser.parse_args()
    scan_variants(args.base_dir)
