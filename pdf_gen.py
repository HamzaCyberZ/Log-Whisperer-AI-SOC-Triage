import re
from fpdf import FPDF

def clean_markdown(text: str) -> str:
    """Strip common Markdown symbols so the PDF looks clean."""
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)  # Remove **bold**
    text = re.sub(r'__(.*?)__', r'\1', text)      # Remove __bold__
    text = re.sub(r'`(.*?)`', r'\1', text)        # Remove `code`
    text = re.sub(r'^#+\s*', '', text, flags=re.MULTILINE)  # Remove ### headers
    return text

def create_pdf(report_text, total_lines, suspicious_lines) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header Banner
    pdf.set_fill_color(15, 23, 42)  # Dark slate header
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 14, "Log Whisperer - SOC Incident Report", new_x="LMARGIN", new_y="NEXT", align="C", fill=True)
    pdf.ln(8)

    # Summary Box
    pdf.set_text_color(30, 41, 59)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Scan Summary", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Total Log Lines Analyzed: {total_lines}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Suspicious Lines Detected: {suspicious_lines}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Divider Line
    pdf.set_draw_color(203, 213, 225)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # AI Analysis Section
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "AI Forensic Analysis", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10.5)
    cleaned_report = clean_markdown(str(report_text))
    safe_text = cleaned_report.encode("latin-1", "replace").decode("latin-1")

    pdf.multi_cell(0, 6.5, safe_text)

    # Handle both fpdf2 (returns bytearray/bytes) and legacy fpdf (returns str)
    output = pdf.output()
    if isinstance(output, str):
        return output.encode("latin-1")
    return bytes(output)