import subprocess
from pathlib import Path
import sys

def build_exe(script_name):
    """Build executable with clean cache"""
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
    Extract .pyc file from PyInstaller EXE using pyinstxtractor.py
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
    else:
        print(f"[DEBUG] ✗ ERROR: {main_pyc_dest} was not created!")
        print(f"[DEBUG] bin_dir contents after failed copy:")
        for item in bin_dir.iterdir():
            print(f"[DEBUG]   {item.name}")
        return None

def generate_report_for_pyc(pyc_path, report_tool="bin/malware_report.exe"):
    """
    Generate a report for the given .pyc file
    """
    pyc_path = Path(pyc_path)
    exe_name = pyc_path.with_suffix('.exe').name
    report_name = pyc_path.parent / f"{exe_name}.pdf"
    
    print(f"Generating report for {pyc_path.name}...")
    report_tool_path = Path(report_tool)
    
    if not report_tool_path.exists():
        print(f"ERROR: Report tool not found: {report_tool_path}")
        return False
    
    if report_tool_path.suffix == ".py":
        cmd = [sys.executable, str(report_tool_path), str(pyc_path), str(report_name)]
    else:
        cmd = [str(report_tool_path), str(pyc_path), str(report_name)]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if Path(report_name).exists():
            print(f"✓ Report generated: {report_name}")
            return True
        else:
            print(f"ERROR: Report not generated for {pyc_path.name}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"ERROR running report tool: {e}")
        if e.stdout:
            print("STDOUT:", e.stdout)
        if e.stderr:
            print("STDERR:", e.stderr)
        return False

def main():
    malware_dir = Path("malware")
    reporting_dir = Path("reporting")
    
    scripts = [
        reporting_dir / "malware_report.py",
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
    
    # PHASE 3: Generate reports for all extracted .pyc files
    print("\n=== PHASE 3: GENERATING REPORTS ===")
    report_success = 0
    
    # First, ensure we have the report tool
    report_tool = Path("bin/malware_report.exe")
    if not report_tool.exists():
        print(f"WARNING: Report tool {report_tool} not found. Skipping report generation.")
        print("Make sure malware_report.py was built successfully in Phase 1.")
    else:
        for pyc_path in extracted_pycs:
            if generate_report_for_pyc(pyc_path, str(report_tool)):
                report_success += 1
            else:
                print(f"✗ Failed to generate report for {pyc_path.name}")
    
    print(f"\nPhase 3 Results: Generated {report_success}/{len(extracted_pycs)} reports")
    
    # FINAL RESULTS
    print(f"\n=== FINAL RESULTS ===")
    print(f"Built: {build_success}/{len(scripts)} executables")
    print(f"Extracted: {extract_success}/{len(built_exes)} .pyc files")
    print(f"Reports: {report_success}/{len(extracted_pycs)} generated")
    
    if build_success > 0:
        print("Executables are in the 'bin' folder")
        print("All your latest changes are included!")
    
    # Return 0 only if all phases completed successfully
    total_expected = len([s for s in scripts if s.exists()])
    return 0 if (build_success == total_expected and extract_success == build_success) else 1

if __name__ == "__main__":
    exit(main())