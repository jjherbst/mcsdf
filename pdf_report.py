from fpdf import FPDF
import datetime

class pdf_report(FPDF):
    """
    pdf_report is a subclass of FPDF designed to generate structured PDF reports for static malware analysis.
    Features:
        - Custom headers and footers with academic/research branding.
        - Section titles and optional subtitles for report organization.
        - Value tables for displaying key-value information.
        - Highlighted text blocks for emphasis.
        - Bullet-point item lists.
        - Formatted code blocks with ASCII-safe rendering.
    """

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=16)
        self.set_margins(18, 20, 18)
        self.set_title("Static Malware Analysis Report")
        self.set_author("Juan Herbst for the dissertation: Master Cyber Securit and Digital Forensics")
        self.set_creator("static_reporter_pdf.py")

    def header(self):
        self.set_font("Arial", "B", 16)
        self.set_text_color(41, 49, 97)
        self.cell(0, 12, "Static Malware Analysis Report", ln=True, align="C")
        self.ln(2)
        self.set_font("Arial", "", 10)
        self.set_text_color(90, 90, 90)
        self.cell(
            0, 7, "By Juan Herbst for the Master Cyber Security and Digital Forensics.", ln=True, align="C")
        self.ln(3)
        self.set_draw_color(100, 120, 200)
        self.set_line_width(0.6)
        self.line(18, self.get_y(), 192, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(128)
        current_year = datetime.datetime.now().year
        self.cell(
            0, 8, f"Page {self.page_no()}   (c) {current_year} Academic Use Only", align="C")

    def section_title(self, title, subtitle=None):
        self.ln(4)
        self.set_font("Arial", "B", 13)
        self.set_text_color(22, 37, 91)
        self.cell(0, 9, title, ln=True)
        if subtitle:
            self.set_font("Arial", "", 10)
            self.set_text_color(95, 120, 160)
            self.cell(0, 7, subtitle, ln=True)
        self.set_text_color(0, 0, 0)
        self.set_font("Arial", "", 10)
        self.ln(1)

    def value_table(self, info_dict):
        self.set_font("Arial", "", 10)
        for key, value in info_dict.items():
            self.cell(43, 7, f"{key}:", border=0)
            self.set_text_color(30, 30, 30)
            self.multi_cell(0, 7, str(value))
            self.set_text_color(0, 0, 0)
        self.ln(1)

    def highlight_text(self, text, color=(240, 247, 255)):
        self.set_fill_color(*color)
        self.set_font("Arial", "I", 10)
        self.multi_cell(0, 7, text, fill=True)
        self.set_font("Arial", "", 10)
        self.ln(1)

    def item_list(self, items, color=(0, 0, 0)):
        self.set_text_color(*color)
        for item in items:
            self.cell(5)
            # Use ASCII bullet point instead of Unicode
            self.multi_cell(0, 6, f"* {item}")
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def code_block(self, text, font_size=8, fill=(245, 245, 245)):
        self.set_font("Courier", "", font_size)
        self.set_fill_color(*fill)
        # Ensure text is ASCII-compatible
        ascii_text = text.encode('ascii', 'replace').decode('ascii')
        self.multi_cell(0, 4.5, ascii_text, fill=True)
        self.ln(1)
        self.set_font("Arial", "", 10)
