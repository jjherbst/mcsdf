#!/usr/bin/env python
"""
Polymorphic Executable Generator

This module generates polymorphic, benign test executables containing the EICAR 
antivirus test signature. Each executable contains the EICAR signature encrypted 
with a unique XOR key to create polymorphic variants while maintaining benign behavior.

The generated executables write identical checksums at runtime, demonstrating 
functional equivalence despite different binary representations.

Usage:
    python generate_polymorphic_exes.py           # Generate 10 variants (default)
    python generate_polymorphic_exes.py -n 5      # Generate 5 variants
    python generate_polymorphic_exes.py --count 3 # Generate 3 variants

Author: Research Project - MCSDF Masters Paper
License: Educational/Research Use
"""

import argparse
import base64
import pathlib
import secrets
import subprocess
import sys
import textwrap

# EICAR antivirus test signature (68 bytes)
# This is a harmless test string used by antivirus software for testing
EICAR_TEST_SIGNATURE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# Python source code template for polymorphic variants
# Each variant will have unique encrypted blob and XOR key values
POLYMORPHIC_VARIANT_TEMPLATE = r'''
# -*- coding: utf-8 -*-
"""
Polymorphic variant executable - Educational/Research purposes only.
This executable demonstrates benign polymorphic variance techniques.
"""
import base64
import csv
import hashlib

# Encrypted EICAR signature and decryption key
encrypted_eicar_blob = "{encrypted_blob}"
xor_decryption_key = {xor_key}

# Decrypt EICAR signature in memory (for demonstration purposes)
decrypted_eicar = bytes(
    byte_value ^ xor_decryption_key 
    for byte_value in base64.b64decode(encrypted_eicar_blob)
)

# Generate consistent checksum for benign payload
payload_checksum = hashlib.sha256(b"benign").hexdigest()

# Write checksum to output file
with open("checksum.csv", "w", newline="", encoding="utf-8") as output_file:
    csv_writer = csv.writer(output_file)
    csv_writer.writerow(["payload_type", "checksum"])
    csv_writer.writerow(["benign", payload_checksum])

print(f"Generated checksum: {{payload_checksum}}")
print("Polymorphic variant executed successfully.")
'''

def generate_xor_encrypted_eicar() -> tuple[str, int]:
    """
    Generate an XOR-encrypted version of the EICAR test signature.
    
    Returns:
        tuple: A tuple containing:
            - Base64-encoded encrypted EICAR signature (str)
            - XOR encryption key used (int)
    """
    xor_key = secrets.randbelow(256)
    encrypted_bytes = bytes(byte_val ^ xor_key for byte_val in EICAR_TEST_SIGNATURE)
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode("ascii")
    
    return encrypted_base64, xor_key


def create_polymorphic_source_code(encrypted_blob: str, xor_key: int) -> str:
    """
    Create the Python source code for a polymorphic variant.
    
    Args:
        encrypted_blob: Base64-encoded encrypted EICAR signature
        xor_key: XOR decryption key for the EICAR signature
        
    Returns:
        str: Complete Python source code for the variant
    """
    return POLYMORPHIC_VARIANT_TEMPLATE.format(
        encrypted_blob=encrypted_blob,
        xor_key=xor_key
    )


def setup_build_directories(base_path: pathlib.Path) -> dict[str, pathlib.Path]:
    """
    Create and return the directory structure for building variants.
    
    Args:
        base_path: Base directory path for the build structure
        
    Returns:
        dict[str, pathlib.Path]: Dictionary containing paths for different build components
    """
    directory_structure = {
        "source_files": base_path / "variants" / "source",
        "executables": base_path / "variants" / "executables", 
        "specifications": base_path / "variants" / "specifications",
        "build_temp": base_path / "build_temp",
    }
    
    # Create all directories
    for directory_path in directory_structure.values():
        directory_path.mkdir(parents=True, exist_ok=True)
    
    return directory_structure


def compile_variant_to_executable(source_file_path: pathlib.Path, 
                                variant_index: int, 
                                build_dirs: dict[str, pathlib.Path]) -> None:
    """
    Compile a Python source file into a standalone executable using PyInstaller.
    
    Args:
        source_file_path: Path to the Python source file
        variant_index: Index number of the variant being built
        build_dirs: Dictionary containing build directory paths
    """
    pyinstaller_command = [
        sys.executable,
        "-m", "PyInstaller",
        "--onefile",                                    # Create single executable file
        "--noconfirm",                                  # Overwrite without confirmation
        "--log-level=INFO",                             # Set logging level
        f"--distpath={build_dirs['executables']}",      # Output directory for executables
        f"--workpath={build_dirs['build_temp'] / f'build_variant_{variant_index}'}",
        f"--specpath={build_dirs['specifications']}",   # Directory for .spec files
        str(source_file_path),
    ]
    
    print(f"[*] Compiling variant {variant_index} to executable...")
    try:
        subprocess.run(pyinstaller_command, check=True, capture_output=False)
        print(f"[✓] Successfully created executable for variant {variant_index}")
    except subprocess.CalledProcessError as error:
        print(f"[✗] Failed to compile variant {variant_index}: {error}")
        raise


def build_single_polymorphic_variant(variant_index: int, 
                                   build_directories: dict[str, pathlib.Path]) -> None:
    """
    Generate, compile, and store a single polymorphic variant executable.
    
    This function creates a unique polymorphic variant by:
    1. Generating a random XOR key and encrypting the EICAR signature
    2. Creating Python source code with the encrypted payload
    3. Compiling the source code into a standalone executable
    
    Args:
        variant_index: Unique identifier/index for this variant
        build_directories: Dictionary containing paths for build components
    """
    # Generate encrypted EICAR signature with random key
    encrypted_blob, xor_key = generate_xor_encrypted_eicar()
    
    # Create Python source code for this variant
    variant_source_code = create_polymorphic_source_code(encrypted_blob, xor_key)
    
    # Write source code to file
    source_file_path = build_directories["source_files"] / f"polymorphic_variant_{variant_index}.py"
    source_file_path.write_text(
        textwrap.dedent(variant_source_code), 
        encoding="utf-8"
    )
    
    # Compile source code to executable
    compile_variant_to_executable(source_file_path, variant_index, build_directories)


def parse_command_line_arguments() -> argparse.Namespace:
    """
    Parse and validate command line arguments.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    argument_parser = argparse.ArgumentParser(
        description="Generate polymorphic benign test executables containing EICAR signatures",
        epilog="This tool is designed for educational and research purposes only."
    )
    
    argument_parser.add_argument(
        "-n", "--count",
        type=int,
        default=10,
        metavar="NUMBER",
        help="Number of polymorphic variants to generate (default: %(default)s)",
    )
    
    argument_parser.add_argument(
        "--output-dir",
        type=pathlib.Path,
        metavar="PATH", 
        help="Custom output directory for generated files (default: auto-generated)"
    )
    
    return argument_parser.parse_args()


def main() -> None:
    """
    Main entry point for the polymorphic executable generator.
    
    This function orchestrates the entire process:
    1. Parse command line arguments
    2. Set up build directory structure
    3. Generate the specified number of polymorphic variants
    4. Report completion status
    """
    print("=== Polymorphic Executable Generator ===")
    print("Generating benign test executables with encrypted EICAR signatures\n")
    
    # Parse command line arguments
    arguments = parse_command_line_arguments()
    
    # Validate argument values
    if arguments.count <= 0:
        print("Error: Number of variants must be greater than 0")
        sys.exit(1)
    
    # Determine base directory for build structure
    if arguments.output_dir:
        base_directory = arguments.output_dir.resolve()
    else:
        base_directory = pathlib.Path(__file__).resolve().with_suffix("")
    
    # Set up build directory structure
    build_directories = setup_build_directories(base_directory)
    
    print(f"Building {arguments.count} polymorphic variant(s)...")
    print(f"Output directory: {build_directories['executables']}\n")
    
    # Generate each polymorphic variant
    for variant_number in range(arguments.count):
        try:
            build_single_polymorphic_variant(variant_number, build_directories)
        except (subprocess.CalledProcessError, OSError, IOError) as error:
            print(f"[✗] Failed to build variant {variant_number}: {error}")
            continue
    
    # Report completion
    print("\n=== Generation Complete ===")
    print(f"Generated variants saved to: {build_directories['executables']}")
    print(f"Source files saved to: {build_directories['source_files']}")
    print(f"Build specifications saved to: {build_directories['specifications']}")
    
    # List generated executables
    executable_files = list(build_directories['executables'].glob("*.exe"))
    if executable_files:
        print(f"\nGenerated {len(executable_files)} executable(s):")
        for exe_file in sorted(executable_files):
            file_size = exe_file.stat().st_size
            print(f"  - {exe_file.name} ({file_size:,} bytes)")
    else:
        print("\nWarning: No executable files were generated successfully.")


if __name__ == "__main__":
    main()
