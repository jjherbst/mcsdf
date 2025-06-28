#!/usr/bin/env python3
"""
generate_report.py: Polymorphic Executable Analysis and Reporting Tool

Usage:
    python generate_report.py [--base-dir PATH]

Dependencies:
    pip install pefile numpy scipy importlib-metadata
"""

import re
import csv
import socket
import hashlib
import platform
from datetime import datetime
from pathlib import Path
from importlib import metadata
import numpy as np
from scipy.stats import entropy as scipy_entropy
import pefile

EICAR_TEST_SIGNATURE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates the Shannon entropy of the given byte data.
    Shannon entropy is a measure of the unpredictability or information content present in the data. The function computes 
    the entropy in bits per byte.

    arguments:
        data (bytes): The input data as a bytes object.

    returns:
        float: The Shannon entropy of the data, rounded to 4 decimal places.
    """
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    return round(scipy_entropy(counts, base=2), 4)

def calculate_file_metadata(path: Path) -> dict:
    """
    Calculates and returns metadata for a given file.

    arguments:
        path (Path): The path to the file.

    returns:
        dict: A dictionary containing the following metadata:
            - filename (str): The name of the file.
            - file_size (int): The size of the file in bytes.
            - sha256 (str): The SHA-256 hash of the file's contents.
            - creation_time (str): The file's creation time in ISO 8601 format (UTC).
            - entropy (float): The Shannon entropy of the file's contents.
            - _data (bytes): The raw bytes of the file.
    """
    stats = path.stat()
    data = path.read_bytes()
    return {
        "filename": path.name,
        "file_size": stats.st_size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "creation_time": datetime.utcfromtimestamp(stats.st_ctime).isoformat()+"Z",
        "entropy": calculate_shannon_entropy(data),
        "_data": data
    }

def calculate_pe_header(data: bytes) -> dict:
    """
    Analyzes a Portable Executable (PE) file from raw bytes and extracts basic statistics.

    arguments:
        data (bytes): The raw bytes of the PE file to analyze.

    returns:
        dict: A dictionary containing:
            - 'section_count' (int or str): The number of sections in the PE file, or an empty string if parsing fails.
            - 'import_count' (int or str): The total number of imported functions, or an empty string if parsing fails.

    exceptions:
        None: Any PE parsing errors are caught and result in empty string values in the returned dictionary.
    """
    try:
        pe = pefile.PE(data=data, fast_load=True)
        sc = len(pe.sections)
        ic = sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
        pe.close()
        return {"section_count": sc, "import_count": ic}
    except pefile.PEFormatError:
        return {"section_count": "", "import_count": ""}

def calculate_strings(data: bytes) -> dict:
    """
    Extracts printable ASCII strings of length 4 or more from a bytes object and returns statistics.

    arguments:
        data (bytes): The binary data to search for ASCII strings.

    returns:
        dict: A dictionary containing:
            - 'num_strings' (int): The number of ASCII strings found.
            - 'longest_string' (int): The length of the longest ASCII string found (0 if none).
    """
    strs = re.findall(rb"[\x20-\x7E]{4,}", data)
    return {"num_strings": len(strs), "longest_string": max((len(s) for s in strs), default=0)}

def calculate_system_info() -> dict:
    """
    Gathers and returns basic system information.

    returns:
        dict: A dictionary containing the following keys:
            - 'hostname': The network name of the machine.
            - 'os_platform': The operating system name and its release version.
            - 'scan_timestamp': The current UTC timestamp in ISO 8601 format with a 'Z' suffix.
    """
    return {
        "hostname": socket.gethostname(),
        "os_platform": f"{platform.system()} {platform.release()}",
        "scan_timestamp": datetime.utcnow().isoformat()+"Z"
    }

def detect_eicar(data: bytes) -> bool:
    """
    Checks if the provided data contains the EICAR test signature.

    arguments:
        data (bytes): The binary data to scan for the EICAR test signature.

    returns:
        bool: True if the EICAR test signature is found in the data, False otherwise.
    """
    return EICAR_TEST_SIGNATURE in data

def parse_source_for_keys(src: Path) -> tuple:
    """
    Parses a Python source file to extract the XOR decryption key, the length of the encrypted EICAR blob, 
    and the build time difference between the corresponding executable and the source file.

    arguments:
        src (Path): The path to the Python source file to be parsed.

    returns:
        tuple: A tuple containing:
            - key (int or str): The extracted XOR decryption key as an integer, or an empty string if not found.
            - blen (int): The length of the base64-encoded encrypted EICAR blob, or 0 if not found.
            - build (float or str): The time difference in seconds (rounded to 2 decimals) between the creation time 
              of the corresponding .exe file and the modification time of the source file, or an empty string if 
              the .exe file does not exist or the time difference is negative.
    """
    txt = src.read_text(encoding="utf-8")
    m1 = re.search(r"xor_decryption_key\s*=\s*(\d+)", txt)
    key = int(m1.group(1)) if m1 else ""
    m2 = re.search(r'encrypted_eicar_blob\s*=\s*"([^"]+)"', txt)
    b64 = m2.group(1) if m2 else ""
    blen = len(b64)
    exe = src.with_suffix(".exe")
    if exe.exists():
        bt = exe.stat().st_ctime - src.stat().st_mtime
        build = round(bt, 2) if bt >= 0 else ""
    else:
        build = ""
    return key, blen, build

def generate_report(base_dir: Path):
    """
    Generates a CSV report containing metadata and analysis results for all polymorphic variant executables found in the specified base directory.

    arguments:
        base_dir (Path): The base directory containing the 'variants' subdirectory with 'source' and 'executables' folders.

    The function performs the following steps:
        - Locates all executables matching 'polymorphic_variant_*.exe' in the 'executables' directory.
        - For each executable, extracts its index, gathers file metadata, analyzes PE headers, extracts strings, and checks for the EICAR test string.
        - Attempts to parse the corresponding Python source file for additional build information (e.g., XOR key, base64 length, build time).
        - Collects environment information such as Python and PyInstaller versions, hostname, OS platform, and timestamp.
        - Writes all collected data into a CSV file named 'benign_polymorphic_variants_report.csv' in the 'variants' directory.

    Prints progress and summary information to the console.
    """
    variants = base_dir / "variants"
    src_dir = variants / "source"
    exe_dir = variants / "executables"
    report_csv = variants / "benign_polymorphic_variants_report.csv"
    report_csv.parent.mkdir(exist_ok=True)

    print(f"[+] Base dir: {base_dir}")
    print(f"[+] Looking for executables in: {exe_dir}")
    # Use correct glob pattern:
    binaries = load_binaries(exe_dir)

    python_version = platform.python_version()
    pi_version = metadata.version("pyinstaller")
    system_info = calculate_system_info()

    fieldnames = set_report_headers()
    with report_csv.open("w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()

        for binary in binaries:
            # extract index from 'polymorphic_variant_<n>.exe'
            idx = calculate_current_index(binary)
            src_py = src_dir / binary.with_suffix(".py").name
            if src_py.exists():
                xor_key, b64_len, build_time = parse_source_for_keys(src_py)
            else:
                xor_key, b64_len, build_time = ("","", "")

            print(f"[++] Processing variant {idx}: {binary.name}")

            file_meta_data = calculate_file_metadata(binary)
            data = file_meta_data.pop("_data") #cache to avoid reading file again
            pe_header = calculate_pe_header(data)
            string_meta_data = calculate_strings(data)
            has_eicar = detect_eicar(data)

            rec = {
                "variant_index": idx,
                **file_meta_data,
                **pe_header,
                **string_meta_data,
                "contains_eicar": has_eicar,
                "xor_key": xor_key,
                "base64_len": b64_len,
                "python_version": python_version,
                "pyinstaller_version": pi_version,
                "build_time_s": build_time,
                **system_info
            }

            writer.writerow(rec)

    print(f"Report written to {report_csv} with {len(binaries)} rows")

def calculate_current_index(binary):
    """
    Extracts and returns the index number from a binary file name following the pattern 'polymorphic_variant_<number>.exe'.

    arguments:
        binary: An object with a 'name' attribute representing the file name as a string.

    returns:
        int or str: The extracted index as an integer if the pattern is found; otherwise, an empty string.
    """
    idx_m = re.search(r"polymorphic_variant_(\d+)\.exe", binary.name)
    idx = int(idx_m.group(1)) if idx_m else ""
    return idx

def load_binaries(exe_dir):
    """
    Loads and returns a sorted list of executable files matching the pattern 'polymorphic_variant_*.exe' from the specified directory.

    arguments:
        exe_dir (Path): The directory to search for executable files.

    returns
        list[Path] or None: A sorted list of Path objects representing the found executables, or None if no executables are found.

    prints:
        The number of executables found, or a warning message if none are found.
    """
    exe_list = sorted(exe_dir.glob("polymorphic_variant_*.exe"))
    print(f"[+] Found {len(exe_list)} executable(s).")

    if not exe_list:
        print("No executables found - check --base-dir and folder structure")

    return exe_list

def set_report_headers():
    """
    returns a list of field names to be used as headers in the generated report.

    The headers include metadata and analysis results for files, such as:
    - variant index
    - filename
    - file size
    - SHA-256 hash
    - creation time
    - entropy
    - section count
    - import count
    - number of strings
    - longest string
    - EICAR test file detection
    - XOR key
    - base64 length
    - Python version
    - PyInstaller version
    - build time in seconds
    - hostname
    - operating system platform
    - scan timestamp

    Returns:
        list[str]: A list of strings representing the report header fields.
    """
    fieldnames = [
        "variant_index","filename","file_size","sha256","creation_time",
        "entropy","section_count","import_count","num_strings","longest_string",
        "contains_eicar","xor_key","base64_len","python_version",
        "pyinstaller_version","build_time_s","hostname","os_platform","scan_timestamp"
    ]
    return fieldnames

if __name__ == "__main__":
    generate_report(Path("./generate_polymorphic_binaries"))