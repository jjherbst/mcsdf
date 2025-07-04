#!/usr/bin/env python3
"""
VirusTotal Malware Analysis Report Generator

This script uploads malware samples to VirusTotal using the official vt-py library,
retrieves comprehensive analysis results, and generates detailed PDF reports.

Features:
- Upload files to VirusTotal using official library
- Retrieve detailed scan results with automatic rate limiting
- Generate comprehensive PDF reports
- Built-in retry logic and error handling
- Support for multiple file uploads
- Detailed vendor analysis breakdown

Usage:
    python virus_total_report.py <malware_file> [--api-key API_KEY] [--output report.pdf]

Requirements:
    pip install vt-py fpdf2

Author: Research Project - MCSDF Masters Paper
License: Educational/Research Use
"""

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import vt
from fpdf import FPDF

class VirusTotalAnalyzer:
    """VirusTotal analyzer using the official vt-py library."""
    
    def __init__(self, api_key: str):
        """
        Initialize VirusTotal analyzer.
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        
    async def analyze_file(self, file_path: Path) -> Optional[Dict]:
        """
        Analyze a file with VirusTotal using the official library.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Analysis results dictionary if successful, None otherwise
        """
        try:
            print(f"[*] Connecting to VirusTotal...")
            
            async with vt.Client(self.api_key) as client:
                # Calculate file hash first
                file_hash = self._calculate_sha256(file_path)
                print(f"[*] File SHA-256: {file_hash}")
                
                # Try to get existing analysis first
                try:
                    print(f"[*] Checking for existing analysis...")
                    file_obj = await client.get_object_async(f"/files/{file_hash}")
                    print(f"[✓] Found existing analysis")
                    return self._convert_vt_object_to_dict(file_obj)
                
                except vt.APIError as e:
                    if e.code == "NotFoundError":
                        print(f"[*] File not found in database, uploading...")
                    else:
                        print(f"[✗] Error checking existing analysis: {e}")
                        return None
                
                # Upload file for analysis
                print(f"[*] Uploading file: {file_path.name}")
                
                with open(file_path, "rb") as f:
                    analysis = await client.scan_file_async(f, wait_for_completion=True)
                
                print(f"[✓] Analysis completed!")
                
                # Get the detailed file report
                file_obj = await client.get_object_async(f"/files/{file_hash}")
                return self._convert_vt_object_to_dict(file_obj)
                
        except vt.APIError as e:
            if "Invalid API key" in str(e):
                print(f"[✗] Invalid API key")
            elif "Quota exceeded" in str(e):
                print(f"[✗] API quota exceeded")
            else:
                print(f"[✗] VirusTotal API error: {e}")
            return None
        except Exception as e:
            print(f"[✗] Unexpected error: {e}")
            return None
    
    def _calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _convert_vt_object_to_dict(self, vt_obj) -> Dict:
        """
        Convert VirusTotal object to dictionary format compatible with existing code.
        
        Args:
            vt_obj: VirusTotal object from vt-py library
            
        Returns:
            Dictionary representation
        """
        # Convert the VT object to a format compatible with our existing PDF generator
        result = {
            "data": {
                "id": vt_obj.id,
                "type": vt_obj.type,
                "attributes": {}
            }
        }
        
        # Copy all attributes from the VT object
        for attr_name in dir(vt_obj):
            if not attr_name.startswith('_') and hasattr(vt_obj, attr_name):
                try:
                    attr_value = getattr(vt_obj, attr_name)
                    # Skip methods and properties that aren't data
                    if not callable(attr_value) and attr_name not in ['id', 'type']:
                        result["data"]["attributes"][attr_name] = attr_value
                except:
                    continue
        
        return result

class VirusTotalPDFReport(FPDF):
    """PDF report generator for VirusTotal analysis results."""
    
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        """PDF header with title and logo placeholder."""
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'VirusTotal Malware Analysis Report', 0, 1, 'C')
        self.ln(10)
        
    def footer(self):
        """PDF footer with page number."""
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
        
    def add_section_title(self, title: str):
        """Add a section title."""
        self.ln(5)
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(2)
        
    def add_key_value(self, key: str, value: str, max_width: int = 180):
        """Add key-value pair with proper formatting."""
        self.set_font('Arial', 'B', 10)
        self.cell(50, 6, f"{key}:", 0, 0, 'L')
        
        self.set_font('Arial', '', 10)
        # Handle long values by wrapping text
        if len(str(value)) > 60:
            lines = self.wrap_text(str(value), 60)
            self.cell(0, 6, lines[0], 0, 1, 'L')
            for line in lines[1:]:
                self.cell(50, 6, '', 0, 0, 'L')  # Indent
                self.cell(0, 6, line, 0, 1, 'L')
        else:
            self.cell(0, 6, str(value), 0, 1, 'L')
        
    def wrap_text(self, text: str, width: int) -> List[str]:
        """Wrap text to specified width."""
        words = text.split(' ')
        lines = []
        current_line = ""
        
        for word in words:
            if len(current_line + word) <= width:
                current_line += word + " "
            else:
                if current_line:
                    lines.append(current_line.strip())
                current_line = word + " "
        
        if current_line:
            lines.append(current_line.strip())
            
        return lines if lines else [text]
    
    def add_detection_table(self, scan_results: Dict):
        """Add detection results table."""
        self.add_section_title("Detection Results")
        
        # Validate scan_results
        if not scan_results or not isinstance(scan_results, dict):
            self.add_key_value("Status", "No scan results available")
            return
        
        # Table headers
        self.set_font('Arial', 'B', 9)
        self.cell(60, 8, 'Antivirus Engine', 1, 0, 'C')
        self.cell(30, 8, 'Result', 1, 0, 'C')
        self.cell(40, 8, 'Version', 1, 0, 'C')
        self.cell(50, 8, 'Update', 1, 1, 'C')
        
        # Table content
        self.set_font('Arial', '', 8)
        
        for engine, details in scan_results.items():
            # Ensure details is not None and is a dictionary
            if not details or not isinstance(details, dict):
                continue
                
            if details.get('category') in ['malicious', 'suspicious']:
                # Malicious/Suspicious - red background
                self.set_fill_color(255, 200, 200)
            elif details.get('category') == 'undetected':
                # Clean - green background
                self.set_fill_color(200, 255, 200)
            else:
                # Other - white background
                self.set_fill_color(255, 255, 255)
            
            engine_name = engine[:25] + "..." if len(engine) > 25 else engine
            result = details.get('result', 'N/A')
            result = result[:25] if result else 'N/A'
            version = details.get('version', 'N/A')
            version = version[:25] if version else 'N/A'
            update = details.get('update', 'N/A')
            update = update[:25] if update else 'N/A'
            
            self.cell(60, 6, engine_name, 1, 0, 'L', True)
            self.cell(30, 6, result, 1, 0, 'L', True)
            self.cell(40, 6, version, 1, 0, 'L', True)
            self.cell(50, 6, update, 1, 1, 'L', True)

def calculate_file_hashes(file_path: Path) -> Dict[str, str]:
    """Calculate multiple hash types for a file."""
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            for hasher in hashes.values():
                hasher.update(chunk)
    
    return {name: hasher.hexdigest() for name, hasher in hashes.items()}

async def analyze_file_with_virustotal(file_path: Path, api_key: str) -> Tuple[Optional[Dict], Dict[str, str]]:
    """
    Complete VirusTotal analysis workflow using official library.
    
    Args:
        file_path: Path to file to analyze
        api_key: VirusTotal API key
        
    Returns:
        Tuple of (analysis_results, file_hashes)
    """
    print(f"=== Analyzing {file_path.name} with VirusTotal ===")
    
    # Calculate file hashes
    file_hashes = calculate_file_hashes(file_path)
    print(f"[*] File SHA-256: {file_hashes['sha256']}")
    
    # Initialize VirusTotal analyzer
    vt_analyzer = VirusTotalAnalyzer(api_key)
    
    # Analyze file
    analysis_data = await vt_analyzer.analyze_file(file_path)
    
    return analysis_data, file_hashes

def generate_comprehensive_pdf_report(analysis_data: Dict, file_hashes: Dict[str, str], 
                                    file_path: Path, output_path: Path) -> bool:
    """
    Generate comprehensive PDF report from VirusTotal analysis.
    
    Args:
        analysis_data: VirusTotal analysis results
        file_hashes: File hash dictionary
        file_path: Original file path
        output_path: Output PDF path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"[*] Generating PDF report: {output_path}")
        
        # Validate analysis data
        if not analysis_data or not isinstance(analysis_data, dict):
            print(f"[✗] Invalid analysis data received")
            return False
        
        # Debug: Print the keys available in analysis_data
        print(f"[DEBUG] Analysis data keys: {list(analysis_data.keys())}")
        
        data_section = analysis_data.get("data")
        if not data_section:
            print(f"[✗] No data section in analysis results")
            print(f"[DEBUG] Available keys: {list(analysis_data.keys())}")
            return False
        
        # Debug: Print the keys available in data section
        print(f"[DEBUG] Data section keys: {list(data_section.keys())}")
        
        attributes = data_section.get("attributes")
        if not attributes:
            print(f"[✗] No attributes section in data")
            print(f"[DEBUG] Data section keys: {list(data_section.keys())}")
            return False
        
        pdf = VirusTotalPDFReport()
        pdf.add_page()
        
        # File Information Section
        pdf.add_section_title("File Information")
        pdf.add_key_value("File Name", file_path.name)
        pdf.add_key_value("File Size", f"{file_path.stat().st_size:,} bytes")
        pdf.add_key_value("Analysis Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
        
        # Hash Information
        pdf.add_section_title("File Hashes")
        pdf.add_key_value("MD5", file_hashes['md5'])
        pdf.add_key_value("SHA-1", file_hashes['sha1'])
        pdf.add_key_value("SHA-256", file_hashes['sha256'])
        
        # Extract analysis attributes safely
        attributes = data_section.get("attributes", {})
        
        # Detection Statistics
        stats = attributes.get("last_analysis_stats", {})
        if stats:
            pdf.add_section_title("Detection Summary")
            
            total_scans = sum(stats.values()) if stats.values() else 0
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            
            pdf.add_key_value("Total Engines", str(total_scans))
            pdf.add_key_value("Malicious Detections", str(malicious))
            pdf.add_key_value("Suspicious Detections", str(suspicious))
            pdf.add_key_value("Clean Results", str(undetected))
            pdf.add_key_value("Detection Ratio", f"{malicious + suspicious}/{total_scans}")
        else:
            pdf.add_section_title("Detection Summary")
            pdf.add_key_value("Status", "No detection statistics available")
        
        # File Type Information
        if "magic" in attributes:
            pdf.add_section_title("File Type Information")
            pdf.add_key_value("Magic", attributes.get("magic", "N/A"))
            pdf.add_key_value("Type Description", attributes.get("type_description", "N/A"))
            pdf.add_key_value("Type Extension", attributes.get("type_extension", "N/A"))
        
        # PE Information (if available)
        pe_info = attributes.get("pe_info", {})
        if pe_info:
            pdf.add_section_title("PE (Portable Executable) Information")
            pdf.add_key_value("Entry Point", str(pe_info.get("entry_point", "N/A")))
            pdf.add_key_value("Imphash", pe_info.get("imphash", "N/A"))
            pdf.add_key_value("Machine Type", str(pe_info.get("machine_type", "N/A")))
            pdf.add_key_value("Timestamp", str(pe_info.get("timestamp", "N/A")))
        
        # YARA Rules (if any)
        yara_rules = attributes.get("crowdsourced_yara_results", [])
        if yara_rules and isinstance(yara_rules, list):
            pdf.add_section_title("YARA Rule Matches")
            for rule in yara_rules[:10]:  # Limit to first 10 rules
                if rule and isinstance(rule, dict):
                    rule_name = rule.get("rule_name", "Unknown")
                    author = rule.get("source", "Unknown")
                    pdf.add_key_value("Rule", f"{rule_name} (by {author})")
        
        # Detailed Detection Results
        scan_results = attributes.get("last_analysis_results", {})
        if scan_results:
            pdf.add_detection_table(scan_results)
        
        # Behavioral Information (if available)
        behavior = attributes.get("behavior", {})
        if behavior and isinstance(behavior, dict):
            pdf.add_section_title("Behavioral Analysis")
            
            # Network activity
            network = behavior.get("network", {})
            if network and isinstance(network, dict):
                dns_lookups = network.get("dns", [])
                if dns_lookups and isinstance(dns_lookups, list):
                    pdf.add_key_value("DNS Lookups", f"{len(dns_lookups)} domains")
                
                http_requests = network.get("http", [])
                if http_requests and isinstance(http_requests, list):
                    pdf.add_key_value("HTTP Requests", f"{len(http_requests)} requests")
        
        # Tags and Names
        tags = attributes.get("tags", [])
        if tags and isinstance(tags, list):
            pdf.add_section_title("Tags")
            # Filter out None values and convert to strings
            valid_tags = [str(tag) for tag in tags if tag is not None]
            if valid_tags:
                pdf.add_key_value("Tags", ", ".join(valid_tags[:20]))  # Limit tags
        
        names = attributes.get("names", [])
        if names and isinstance(names, list):
            pdf.add_section_title("Known Names")
            for name in names[:10]:  # Limit to first 10 names
                if name is not None:
                    pdf.add_key_value("Name", str(name))
        
        # Save PDF
        pdf.output(str(output_path))
        print(f"[✓] PDF report generated: {output_path}")
        return True
        
    except Exception as error:
        import traceback
        print(f"[✗] Error generating PDF report: {error}")
        print(f"[DEBUG] Full traceback:")
        traceback.print_exc()
        return False

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VirusTotal Malware Analysis Report Generator",
        epilog="This tool uploads malware samples to VirusTotal and generates comprehensive PDF reports."
    )
    
    parser.add_argument(
        "file_path",
        type=Path,
        help="Path to the malware file to analyze"
    )
    
    parser.add_argument(
        "--api-key",
        type=str,
        help="VirusTotal API key (or set VT_API_KEY environment variable)"
    )
    
    parser.add_argument(
        "--output",
        type=Path,
        help="Output PDF report path (default: <filename>_vt_report.pdf)"
    )
    
    parser.add_argument(
        "--wait-time",
        type=int,
        default=300,
        help="Maximum time to wait for analysis completion (seconds, default: 300)"
    )
    
    return parser.parse_args()

async def main_async() -> int:
    """Main async entry point."""
    print("=== VirusTotal Malware Analysis Report Generator ===")
    print("Educational/Research Tool - MCSDF Masters Paper")
    print("Using Official VirusTotal Python Library (vt-py)\n")
    
    # Parse arguments
    args = parse_arguments()
    
    # Validate file
    if not args.file_path.exists():
        print(f"[✗] File not found: {args.file_path}")
        return 1
    
    if not args.file_path.is_file():
        print(f"[✗] Not a file: {args.file_path}")
        return 1
    
    # Get API key
    api_key = args.api_key or os.getenv("VT_API_KEY")
    if not api_key:
        print("[✗] VirusTotal API key required. Use --api-key or set VT_API_KEY environment variable.")
        print("Get your free API key at: https://www.virustotal.com/gui/join-us")
        return 1
    
    # Set output path
    if args.output:
        output_path = args.output
    else:
        output_path = args.file_path.parent / f"{args.file_path.stem}_vt_report.pdf"
    
    try:
        # Analyze file with VirusTotal
        analysis_data, file_hashes = await analyze_file_with_virustotal(args.file_path, api_key)
        
        if not analysis_data:
            print("[✗] Failed to get VirusTotal analysis results")
            print("[*] This could be due to:")
            print("    - Invalid API key")
            print("    - File too large (>32MB for free accounts)")
            print("    - Network connectivity issues")
            print("    - VirusTotal service temporarily unavailable")
            return 1
        
        # Generate PDF report
        success = generate_comprehensive_pdf_report(
            analysis_data, file_hashes, args.file_path, output_path
        )
        
        if success:
            print(f"\n[✓] Analysis complete! Report saved to: {output_path}")
            return 0
        else:
            print(f"\n[✗] Failed to generate report")
            return 1
            
    except KeyboardInterrupt:
        print("\n[*] Analysis interrupted by user")
        return 1
    except Exception as error:
        print(f"\n[✗] Unexpected error: {error}")
        return 1

def main() -> int:
    """Main entry point that runs the async function."""
    return asyncio.run(main_async())

if __name__ == "__main__":
    sys.exit(main())
