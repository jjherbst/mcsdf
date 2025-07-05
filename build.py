#!/usr/bin/env python3
"""
Simple Build Script - Builds fresh executables and automates unpack+report
"""

import subprocess
from pathlib import Path
import sys

def build_exe(script_name):
    """Build executable with clean cache"""
    exe_name = script_name.replace('.py', '.exe')
    print(f"Building {exe_name}...")
    
    cmd = [
        "pyinstaller", 
        "--onefile", 
        "--clean", 
        "--noconfirm",
        "--distpath", "bin",
        "--specpath", "spec",
        "--debug=all",
        script_name
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0 and Path(f"bin/{exe_name}").exists():
        size = Path(f"bin/{exe_name}").stat().st_size
        print(f"{exe_name} built successfully ({size:,} bytes)")
        return True
    else:
        print(f"{exe_name} build failed")
        if result.stderr:
            print("--- PyInstaller Error Output ---")
            print(result.stderr)
        if result.stdout:
            print("--- PyInstaller Standard Output ---")
            print(result.stdout)
        return False

def unpack_and_report(exe_path, report_tool="bin/generate_malware_report.exe"):
    """
    Unpack the PyInstaller EXE and run the reporting tool on the main .pyc file.
    Everything stays in the bin folder.
    """
    exe_path = Path(exe_path)
    exe_name = exe_path.name
    extracted_dir = Path("bin") / f"{exe_path.stem}_extracted"

    # 1. Unpack (into bin folder)
    print(f"Unpacking {exe_name}...")
    result = subprocess.run([sys.executable, "./bin/pyinstxtractor.py", str(exe_path)], capture_output=True, text=True)
    print(result.stdout)

    # pyinstxtractor creates the directory next to the exe, so we need to move it to bin
    original_extracted = Path(f"{exe_name}_extracted")  # Created with full exe name including .exe
    target_extracted = Path("bin") / f"{exe_path.stem}_extracted"  # Where we want it (without .exe)
    
    # Move the extracted directory to bin folder if it exists in current directory
    if original_extracted.exists() and not target_extracted.exists():
        import shutil
        shutil.move(str(original_extracted), str(target_extracted))
        print(f"Moved extracted directory to {target_extracted}")
    
    extracted_dir = target_extracted

    # 2. Find main .pyc - look for the script with the same name as the exe
    pyc_files = list(extracted_dir.rglob("*.pyc"))
    if not pyc_files:
        print(f"No .pyc files found in {extracted_dir}")
        return False

    # Look for the main script file first (e.g., malware.pyc)
    script_name = exe_path.stem  # e.g., "malware"
    main_pyc = None
    
    # First, try to find the exact script name
    for pyc_file in pyc_files:
        if pyc_file.stem == script_name:
            main_pyc = pyc_file
            break
    
    # If not found, look for it in subdirectories
    if not main_pyc:
        for pyc_file in pyc_files:
            if script_name in pyc_file.name:
                main_pyc = pyc_file
                break
    
    # Fall back to largest file if main script not found
    if not main_pyc:
        main_pyc = max(pyc_files, key=lambda p: p.stat().st_size)
        print(f"Main script not found, using largest .pyc file")
    
    print(f"Found .pyc: {main_pyc}")

    # 3. Run report tool (save report in bin folder)
    report_name = f"bin/report_{exe_name}.pdf"
    print(f"Running report tool: {report_tool} {main_pyc} {report_name}")
    subprocess.run([report_tool, str(main_pyc), report_name])

    if Path(report_name).exists():
        print(f"Report generated: {report_name}")
        return True
    else:
        print(f"Report not generated for {exe_name}")
        return False

def main():
    print("=== BUILDING EXECUTABLES ===")
    # Use absolute paths to scripts in the malware directory
    malware_dir = Path("malware")
    reporting_dir = Path("reporting")
    scripts = [
        malware_dir / "malware.py",
        malware_dir / "polymorphic_ransomware.py",
        malware_dir / "metamorphic_ransomware.py",
        malware_dir / "ransomware.py",
        malware_dir / "build_ransomware_environment.py",
        reporting_dir / "malware_report.py"
    ]
    success = 0

    for script in scripts:
        if script.exists():
            if build_exe(str(script)):
                success += 1
        else:
            print(f"✗ {script} not found")
    
    print(f"\n=== RESULTS ===")
    print(f"Built {success}/{len(scripts)} executables successfully")
    
    if success > 0:
        print("Executables are in the 'bin' folder")
        print("All your latest changes are included!\n")

        # Optionally automate unpack+report for your trigger EXE
        exe_path = "bin/malware.exe"
        if Path(exe_path).exists():
            unpack_and_report(exe_path, report_tool="bin/generate_malware_report.exe")
    
    return 0 if success == len(scripts) else 1

if __name__ == "__main__":
    exit(main())