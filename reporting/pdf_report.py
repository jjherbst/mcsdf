
"""
Professional PDF Report Generator - Advanced PDF creation system for 
malware analysis reports with dynamic sections, formatted tables, and 
professional styling designed for academic cybersecurity research and 
comprehensive threat intelligence documentation.
"""
from fpdf import FPDF
from datetime import datetime as dt

class MalwareAnalysisReport(FPDF):
    """
    description: Professional PDF report generator for malware analysis with dynamic sections and formatted output
    parameters: None (inherits from FPDF)
    returns: MalwareAnalysisReport instance with comprehensive PDF generation capabilities for malware research
    """
    def mitre_attack_table(self, mitre_list):
        """
        description: Displays MITRE ATT&CK techniques in formatted table with technique IDs, tactics, and descriptions
        parameters: mitre_list (List[Dict]) - list of MITRE ATT&CK technique dictionaries with technique details
        returns: None, adds formatted MITRE ATT&CK table to PDF report for threat intelligence analysis
        """
        if not mitre_list:
            self.highlight_text("No MITRE ATT&CK techniques reported by VirusTotal.")
            return
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(60, 60, 120)
        self.cell(40, 7, "Technique ID", border=1)
        self.cell(70, 7, "Technique", border=1)
        self.cell(40, 7, "Tactic", border=1)
        self.cell(0, 7, "Framework", border=1, new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(0, 0, 0)
        for entry in mitre_list:
            tid = entry.get("technique_id", "?")
            tname = entry.get("technique", "?")
            tactic = entry.get("tactic", "?")
            framework = entry.get("framework", "MITRE ATT&CK")
            self.cell(40, 6, str(tid), border=1)
            self.cell(70, 6, str(tname), border=1)
            self.cell(40, 6, str(tactic), border=1)
            self.cell(0, 6, str(framework), border=1, new_x="LMARGIN", new_y="NEXT")
            desc = entry.get("description")
            if desc:
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(80, 80, 120)
                self.multi_cell(0, 5, f"    {desc}")
                self.set_font("Helvetica", "", 9)
                self.set_text_color(0, 0, 0)
        self.ln(2)

    def __init__(self):
        """
        description: Initializes PDF report with professional settings, margins, and metadata for malware analysis documentation
        parameters: None
        returns: None, configures PDF document properties and page layout for academic report generation
        """
        super().__init__()
        self.set_auto_page_break(auto=True, margin=16)
        self.set_margins(18, 20, 18)
        self.set_title("Malware Analysis & Detection Report")
        self.set_author("Juan Herbst - Master Cyber Security and Digital Forensics")
        self.set_creator("malware_report.py")
        self.current_section = "General"  
        self._section_separator_pages = set()  
        self._section_first_pages = set()  

    def virustotal_summary_table(self, summary_dict):
        """
        description: Displays VirusTotal v3 API summary attributes in formatted table for threat intelligence overview
        parameters: summary_dict (Dict) - dictionary containing pre-extracted VirusTotal summary attributes and metadata
        returns: None, adds formatted VirusTotal summary table to PDF report for external intelligence analysis
        """
        if not summary_dict or not isinstance(summary_dict, dict):
            self.highlight_text("No VirusTotal summary data available.")
            return
        # Only show non-empty values
        info_dict = {k: v for k, v in summary_dict.items() if v}
        if not info_dict:
            self.highlight_text("No VirusTotal summary attributes available.")
            return
        self.value_table(info_dict)

    def set_section(self, section_name):
        """
        description: Sets current report section for dynamic header generation and document organization
        parameters: section_name (str) - name of the current section for header and navigation purposes
        returns: None, updates internal section state for dynamic PDF formatting and organization
        """
        self.current_section = section_name

    def header(self):
        """
        description: Generates dynamic page headers based on current section with professional styling and branding
        parameters: None
        returns: None, adds section-specific headers to PDF pages for document navigation and organization
        """
        # Subtle header: 
        if self.page_no() == 1:
            return
        if hasattr(self, '_section_separator_pages') and self.page_no() in self._section_separator_pages:
            return
        self.set_font("Helvetica", "", 10)
        self.set_text_color(120, 130, 160)
        if self.current_section == "MCSDF Static Analysis":
            header_text = "MCSDF Malware Analysis Result"
        elif self.current_section == "VirusTotal":
            header_text = "External Threat Intelligence Results"
        else:
            return
        self.set_y(8)
        self.cell(0, 7, header_text, new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(0.5)
        self.set_draw_color(180, 190, 220)
        self.set_line_width(0.3)
        self.line(18, self.get_y(), 192, self.get_y())
        self.ln(1)

    def footer(self):
        """
        description: Generates professional footer with page numbers and academic copyright information
        parameters: None
        returns: None, adds consistent footer styling to all PDF pages for professional presentation
        """
        if self.page_no() == 1:
            return
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128)
        current_year = dt.now().year
        self.cell(0, 8, f"Page {self.page_no()}   © {current_year} Academic Research - MCSDF", align="C")

    def section_title(self, title, subtitle=None):
        """
        description: Adds formatted section titles with optional subtitles for document organization and readability
        parameters: title (str) - main section title text, subtitle (Optional[str]) - optional descriptive subtitle
        returns: None, adds professionally styled section headings to PDF for content organization
        """
        if hasattr(self, '_section_separator_pages') and self.page_no() in self._section_separator_pages:
            return
        if hasattr(self, '_pages_with_section_title'):
            self._pages_with_section_title.add(self.page_no())
        else:
            self._pages_with_section_title = {self.page_no()}
        self.set_text_color(0, 0, 0)  # Reset to black
        self.ln(4)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(22, 37, 91)
        self.cell(0, 9, title, new_x="LMARGIN", new_y="NEXT")
        if subtitle:
            self.set_font("Helvetica", "", 10)
            self.set_text_color(95, 120, 160)
            self.cell(0, 7, subtitle, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "", 10)

    def add_main_section_separator(self, section_title, section_subtitle=None):
        """
        description: Creates major section separator page with centered title and professional styling for document structure
        parameters: section_title (str) - main section title, section_subtitle (Optional[str]) - optional section description
        returns: None, adds new page with centered section separator for major report divisions
        """
        if "MCSDF" in section_title or "Static" in section_title:
            self.set_section("MCSDF Static Analysis")
        elif "VirusTotal" in section_title:
            self.set_section("VirusTotal")
        else:
            self.set_section("General")
        if not hasattr(self, '_section_separator_pages'):
            self._section_separator_pages = set()
        self._adding_separator = True
        self.add_page()
        self._adding_separator = False
        self._section_separator_pages.add(self.page_no())
        # Draw a line above the section title
        y_top = self.h / 2 - 28
        self.set_draw_color(22, 37, 91)
        self.set_line_width(0.7)
        self.line(50, y_top, 160, y_top)
        self.set_y(self.h / 2 - 20)
        self.set_text_color(22, 37, 91)
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 12, section_title, align="C", new_x="LMARGIN", new_y="NEXT")
        if section_subtitle:
            self.set_font("Helvetica", "", 11)
            self.set_text_color(95, 120, 160)
            self.cell(0, 8, section_subtitle, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(8)
        # Draw a line below the section title (existing)
        self.set_draw_color(22, 37, 91)
        self.set_line_width(0.7)
        self.line(50, self.get_y(), 160, self.get_y())
        self.ln(8)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(0, 0, 0)
        self.set_draw_color(0, 0, 0)
        self.set_line_width(0.2)

    def value_table(self, info_dict):
        """
        description: Displays key-value pairs in formatted table layout for structured information presentation
        parameters: info_dict (Dict) - dictionary containing key-value pairs for tabular display
        returns: None, adds formatted table to PDF with keys and corresponding values for data presentation
        """
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "", 10)
        for key, value in info_dict.items():
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(50, 50, 50)
            self.cell(40, 7, f"{key}:", border=0)
            self.set_font("Helvetica", "", 10)
            self.set_text_color(0, 0, 0)
            self.cell(0, 7, str(value)[:100], new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def highlight_text(self, text, color=(240, 247, 255)):
        """
        description: Adds highlighted text blocks with colored background for emphasis and important information
        parameters: text (str) - text content to highlight, color (Tuple[int, int, int]) - RGB background color values
        returns: None, adds highlighted text block to PDF with specified background color for visual emphasis
        """
        self.set_fill_color(*color)
        self.set_font("Helvetica", "I", 10)
        self.multi_cell(0, 7, text, fill=True)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(0, 0, 0)
        self.ln(2)  # Consistent spacing

    def item_list(self, items, color=(0, 0, 0)):
        """
        description: Displays bullet-point list with custom text color for organized information presentation
        parameters: items (List[str]) - list of items to display as bullets, color (Tuple[int, int, int]) - RGB text color
        returns: None, adds formatted bullet-point list to PDF with specified text color for content organization
        """
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*color)
        for item in items:
            self.cell(5)
            safe_item = str(item)[:120] + "..." if len(str(item)) > 120 else str(item)
            self.cell(0, 6, f"- {safe_item}", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "", 10)
        self.ln(2)

    def detection_table(self, scan_results):
        """
        description: Creates formatted table of VirusTotal antivirus detection results with color-coded status indicators
        parameters: scan_results (Dict) - dictionary containing antivirus engine results and detection details
        returns: None, adds comprehensive detection results table to PDF with color-coded threat indicators
        """
        if not scan_results or not isinstance(scan_results, dict):
            self.highlight_text("No VirusTotal scan results available")
            return
        self.set_font('Helvetica', 'B', 9)
        self.cell(50, 8, 'Antivirus Engine', 1, 0, 'C')
        self.cell(35, 8, 'Result', 1, 0, 'C')
        self.cell(30, 8, 'Version', 1, 0, 'C')
        self.cell(30, 8, 'Update', 1, 1, 'C')
        self.set_font('Helvetica', '', 8)
        count = 0
        for engine, details in scan_results.items():
            if count >= 20:  # Limit to first 20 results
                break
            if not details or not isinstance(details, dict):
                continue
            if details.get('category') in ['malicious', 'suspicious']:
                self.set_fill_color(255, 200, 200)  # Red background
            elif details.get('category') == 'undetected':
                self.set_fill_color(200, 255, 200)  # Green background
            else:
                self.set_fill_color(255, 255, 255)  # White background
            engine_name = engine[:22] + "..." if len(engine) > 22 else engine
            result = details.get('result', 'N/A')
            result = result[:32] if result else 'Clean'
            version = details.get('version', 'N/A')
            version = version[:27] if version else 'N/A'
            update = details.get('update', 'N/A')
            update = update[:27] if update else 'N/A'
            self.cell(50, 6, engine_name, 1, 0, 'L', True)
            self.cell(35, 6, result, 1, 0, 'L', True)
            self.cell(30, 6, version, 1, 0, 'L', True)
            self.cell(30, 6, update, 1, 1, 'L', True)
            count += 1
        if count >= 20:
            self.ln(2)
            self.highlight_text(f"Showing first 20 results. Total engines: {len(scan_results)}")

    def ascii_strings_table(self, ascii_strings, columns=3, max_strings=100):
        """
        description: Displays extracted ASCII strings in multi-column table format for malware string analysis
        parameters: ascii_strings (List[str]) - extracted strings from binary, columns (int) - table columns, max_strings (int) - maximum strings to display
        returns: None, adds formatted multi-column string table to PDF for comprehensive string analysis presentation
        """
        display_strings = (
            ascii_strings[:max_strings]
            if len(ascii_strings) > max_strings
            else ascii_strings
        )
        self.set_font("Helvetica", "", 7)
        col_width = (self.w - 2 * self.l_margin) / columns
        self.set_fill_color(245, 245, 245)
        self.set_text_color(40, 40, 40)
        rows = [
            display_strings[i: i + columns]
            for i in range(0, len(display_strings), columns)
        ]
        for row in rows:
            for col in range(columns):
                val = row[col] if col < len(row) else ""
                val = val[:25] + "..." if len(val) > 25 else val
                self.cell(col_width, 4, val, border=0, align="L", fill=True)
            self.ln(4)
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "", 10)
        if len(ascii_strings) > max_strings:
            self.highlight_text(
                f"...{len(ascii_strings)-max_strings} more strings omitted for brevity."
            )

    def add_cover_page(self, file_name: str, analysis_date: str):
        """
        description: Creates professional cover page with title, file information, and academic branding for report presentation
        parameters: file_name (str) - name of analyzed malware file, analysis_date (str) - date of analysis execution
        returns: None, adds formatted cover page to PDF with academic information and professional styling
        """
        self.add_page()
        self.set_font("Helvetica", "B", 24)
        self.set_text_color(0, 0, 0)
        self.ln(30)
        self.cell(0, 15, "Malware", new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 15, "Analysis & Detection Report", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(10)
        self.set_font("Helvetica", "", 14)
        self.set_text_color(60, 60, 60)
        self.cell(0, 10, "Custom Static Analysis & VirusTotal Intelligence", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(20)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(0, 0, 0)
        self.cell(0, 8, "Analyzed Sample:", new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("Helvetica", "", 12)
        self.cell(0, 8, file_name, new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(5)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, f"Analysis Date: {analysis_date}", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(30)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, "Juan Herbst (13840146)", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(10)
        self.set_font("Helvetica", "", 12)
        self.cell(0, 9, "Auckland University of Technology", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(10)
        self.set_font("Helvetica", "", 12)
        self.cell(0, 8, "COMP997", new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 8, "Master of Cyber Security and Digital Forensics", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(30)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(80, 80, 80)
        disclaimer_text = ("This report is generated for academic research purposes as part of the Master of Cyber Security and Digital Forensics "
                          "program. The analysis combines automated static analysis techniques with VirusTotal intelligence.")
        self.multi_cell(0, 6, disclaimer_text, align="C")
        self.set_text_color(0, 0, 0)

    def add_page(self, orientation='', size='', same=False):
        """
        description: Overrides FPDF add_page method to manage section separator flags and page state tracking
        parameters: orientation (str) - page orientation, size (str) - page size, same (bool) - same page settings flag
        returns: None, adds new page while maintaining section separator state for proper document formatting
        """
        super().add_page(orientation, size, same)
        # Reset separator flag for all new pages EXCEPT when we're in add_main_section_separator
        if not hasattr(self, '_adding_separator') or not self._adding_separator:
            self._current_page_is_separator = False
