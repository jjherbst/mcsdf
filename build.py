"""
Automated Malware Build System - Comprehensive build automation tool that 
compiles Python malware simulations into executables using PyInstaller and 
extracts bytecode for static analysis, designed for academic cybersecurity 
research and malware detection system testing environments.
"""
import subprocess
from pathlib import Path
import sys

def build_exe(script_name):
    """
    description: Builds standalone executable from Python script using PyInstaller with optimized settings for malware simulation
    parameters: script_name (str) - path to Python script file for compilation into standalone executable
    returns: bool indicating successful executable creation and verification in bin directory
    """
    script_path = Path(script_name)
    exe_name = script_path.stem + '.exe'  # Just the filename, not the full path
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
    
    exe_path = Path("bin") / exe_name  # Correct path in bin directory
    if result.returncode == 0 and exe_path.exists():
        size = exe_path.stat().st_size
        print(f"✓ {exe_name} built successfully ({size:,} bytes)")
        return True
    else:
        print(f"✗ {exe_name} build failed")
        if result.stderr:
            print("--- PyInstaller Error Output ---")
            print(result.stderr)
        if result.stdout:
            print("--- PyInstaller Standard Output ---")
            print(result.stdout)
        return False

def extract_pyc_from_exe(exe_path):
    """
    description: Extracts Python bytecode (.pyc) files from PyInstaller executables using pyinstxtractor for static analysis
    parameters: exe_path (Path or str) - path to PyInstaller executable for bytecode extraction and analysis preparation
    returns: Path to extracted .pyc file in bin directory or None if extraction fails or file not found
    """
    exe_path = Path(exe_path)
    exe_name = exe_path.name
    import shutil

    print(f"Extracting .pyc from {exe_name}...")
    bin_dir = exe_path.parent.resolve()
    project_root = Path(__file__).parent.resolve()
    exe_full_path = bin_dir / exe_name
    
    print(f"[DEBUG] bin_dir: {bin_dir}")
    print(f"[DEBUG] project_root: {project_root}")
    print(f"[DEBUG] exe_full_path: {exe_full_path}")
    
    if not exe_full_path.exists():
        print(f"ERROR: EXE does not exist: {exe_full_path}")
        return None
    
    extractor_path = bin_dir / "pyinstxtractor.py"
    if not extractor_path.exists():
        print(f"ERROR: pyinstxtractor.py not found: {extractor_path}")
        return None
    
    print(f"Running extractor: {sys.executable} {extractor_path} {exe_name} (cwd={bin_dir})")
    result = subprocess.run([
        sys.executable,
        str(extractor_path),
        exe_name  # Use just the exe name since we're in bin directory
    ], capture_output=True, text=True, cwd=str(bin_dir))  # Run from bin directory
    
    print("--- pyinstxtractor.py STDOUT ---")
    print(result.stdout)
    if result.stderr:
        print("--- pyinstxtractor.py STDERR ---")
        print(result.stderr)

    # Look for extracted directory in bin folder
    extracted_dir = bin_dir / f"{exe_name}_extracted"
    print(f"[DEBUG] Looking for extracted dir at: {extracted_dir}")
    if not extracted_dir.exists():
        print(f"ERROR: Extracted directory not found: {extracted_dir}")
        return None
    
    # Find and copy the .pyc file with the same base name as the exe
    target_pyc_name = f"{exe_path.stem}.pyc"
    print(f"[DEBUG] Looking for .pyc file: {target_pyc_name}")
    found_pyc = None
    
    print(f"[DEBUG] Searching for .pyc files in {extracted_dir}:")
    all_pyc_files = list(extracted_dir.rglob("*.pyc"))
    for pyc in all_pyc_files:
        print(f"[DEBUG] Found .pyc: {pyc.name} at {pyc}")
        if pyc.name == target_pyc_name:
            found_pyc = pyc
            print(f"[DEBUG] ✓ MATCH: {pyc.name} == {target_pyc_name}")
            break
        else:
            print(f"[DEBUG] No match: {pyc.name} != {target_pyc_name}")
    
    if not found_pyc:
        print(f"ERROR: Expected .pyc file not found: {target_pyc_name} in {extracted_dir}")
        print(f"[DEBUG] Available .pyc files: {[p.name for p in all_pyc_files]}")
        return None
    
    main_pyc_dest = bin_dir / target_pyc_name
    print(f"[DEBUG] Source file: {found_pyc}")
    print(f"[DEBUG] Destination: {main_pyc_dest}")
    print(f"[DEBUG] bin_dir contents before copy:")
    for item in bin_dir.iterdir():
        print(f"[DEBUG]   {item.name}")
    
    try:
        shutil.copy2(found_pyc, main_pyc_dest)
        print(f"✓ Copy operation completed: {found_pyc} → {main_pyc_dest}")
    except Exception as e:
        print(f"ERROR during copy: {e}")
        return None
    
    # Verify the file was actually copied
    if main_pyc_dest.exists():
        size = main_pyc_dest.stat().st_size
        print(f"[DEBUG] ✓ Confirmed: {main_pyc_dest} exists ({size} bytes)")
        
        print(f"[DEBUG] bin_dir contents after copy:")
        for item in bin_dir.iterdir():
            if item.suffix == '.pyc':
                print(f"[DEBUG]   ✓ {item.name}")
            else:
                print(f"[DEBUG]   {item.name}")
        
        return main_pyc_dest  # IMPORTANT: Return the path to the copied .pyc file
    else:
        print(f"[DEBUG] ✗ ERROR: {main_pyc_dest} was not created!")
        print(f"[DEBUG] bin_dir contents after failed copy:")
        for item in bin_dir.iterdir():
            print(f"[DEBUG]   {item.name}")
        return None



def main():
    """
    description: Main orchestration function that automates complete build process for malware simulation suite
    parameters: None
    returns: int exit code (0 for complete success, 1 for partial or complete failure) indicating build process status
    """
    malware_dir = Path("malware")
    reporting_dir = Path("reporting")
    
    scripts = [
        # reporting_dir / "malware_report.py",  # Excluded - use Python script directly
        malware_dir / "malware.py",
        malware_dir / "polymorphic_ransomware.py",
        malware_dir / "metamorphic_ransomware.py",
        malware_dir / "ransomware.py",
        malware_dir / "build_ransomware_environment.py"
    ]
    
    # PHASE 1: Build all EXEs
    print("\n=== PHASE 1: BUILDING EXECUTABLES ===")
    built_exes = []
    build_success = 0
    
    for script in scripts:
        if script.exists():
            exe_name = script.with_suffix('.exe').name
            exe_path = Path("bin") / exe_name
            
            if build_exe(str(script)):
                build_success += 1
                if exe_path.exists():
                    built_exes.append(exe_path)
                    print(f"{exe_name} built and added to processing list")
                else:
                    print(f"{exe_name} build reported success but file not found")
            else:
                print(f"{exe_name} build failed")
        else:
            print(f"{script} not found")
    
    print(f"\nPhase 1 Results: Built {build_success}/{len(scripts)} executables")
    
    # PHASE 2: Extract .pyc files from all built EXEs
    print("\n=== PHASE 2: EXTRACTING .PYC FILES ===")
    extracted_pycs = []
    extract_success = 0
    
    for exe_path in built_exes:
        pyc_path = extract_pyc_from_exe(exe_path)
        if pyc_path:
            extracted_pycs.append(pyc_path)
            extract_success += 1
        else:
            print(f"Failed to extract .pyc from {exe_path.name}")
    
    print(f"\nPhase 2 Results: Extracted {extract_success}/{len(built_exes)} .pyc files")
    
    # FINAL RESULTS
    print(f"\n=== FINAL RESULTS ===")
    print(f"Built: {build_success}/{len(scripts)} executables")
    print(f"Extracted: {extract_success}/{len(built_exes)} .pyc files")
    
    if build_success > 0:
        print("Executables are in the 'bin' folder")
        print("All your latest changes are included!")
    
    # Show extracted .pyc files
    if extract_success > 0:
        print(f"\n[DEBUG] Extracted .pyc files in bin folder:")
        bin_dir = Path("bin")
        pyc_files = list(bin_dir.glob("*.pyc"))
        for pyc in pyc_files:
            size = pyc.stat().st_size
            print(f"[DEBUG]   ✓ {pyc.name} ({size} bytes)")
        if not pyc_files:
            print(f"[DEBUG]   No .pyc files found in {bin_dir}")
    
    # Return 0 only if all phases completed successfully
    total_expected = len([s for s in scripts if s.exists()])
    return 0 if (build_success == total_expected and extract_success == build_success) else 1

if __name__ == "__main__":
    exit(main())