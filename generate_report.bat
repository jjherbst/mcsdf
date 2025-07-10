@echo off
REM Malware Analysis Report Generation Script
REM This script generates comprehensive reports for all malware samples

set API_KEY=d663e661563ec1b91a40086b3506645fd6af544eecf25fe59027dd5940e20532
set OUTPUT_DIR=bin

echo === Generating Malware Analysis Reports ===
echo.

echo Generating report for: malware
python -m reporting.malware_report malware --output %OUTPUT_DIR%/malware_report.pdf --api-key %API_KEY%
if %errorlevel% equ 0 (
    echo ✓ Report generated successfully: %OUTPUT_DIR%/malware_report.pdf
) else (
    echo ✗ Failed to generate report for: malware
)
echo.

echo Generating report for: ransomware
python -m reporting.malware_report ransomware --output %OUTPUT_DIR%/ransomware.pdf --api-key %API_KEY%
if %errorlevel% equ 0 (
    echo ✓ Report generated successfully: %OUTPUT_DIR%/ransomware.pdf
) else (
    echo ✗ Failed to generate report for: ransomware
)
echo.

echo Generating report for: polymorphic_ransomware
python -m reporting.malware_report polymorphic_ransomware --output %OUTPUT_DIR%/polymorphic_ransomware.pdf --api-key %API_KEY%
if %errorlevel% equ 0 (
    echo ✓ Report generated successfully: %OUTPUT_DIR%/polymorphic_ransomware.pdf
) else (
    echo ✗ Failed to generate report for: polymorphic_ransomware
)
echo.

echo Generating report for: metamorphic_ransomware
python -m reporting.malware_report metamorphic_ransomware --output %OUTPUT_DIR%/metamorphic_ransomware.pdf --api-key %API_KEY%
if %errorlevel% equ 0 (
    echo ✓ Report generated successfully: %OUTPUT_DIR%/metamorphic_ransomware.pdf
) else (
    echo ✗ Failed to generate report for: metamorphic_ransomware
)
echo.

echo Generating report for: build_ransomware_environment
python -m reporting.malware_report build_ransomware_environment --output %OUTPUT_DIR%/build_ransomware_environment.pdf --api-key %API_KEY%
if %errorlevel% equ 0 (
    echo ✓ Report generated successfully: %OUTPUT_DIR%/build_ransomware_environment.pdf
) else (
    echo ✗ Failed to generate report for: build_ransomware_environment
)
echo.

echo === Report Generation Complete ===
pause
