"""
PDF Report Generator
Produces a professional PDF report from a ScanResult using reportlab.
"""

from datetime import datetime
from html import escape
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from scanner.core import ScanResult

# Color palette
C_BG = colors.HexColor("#0d1117")
C_SURFACE = colors.HexColor("#161b22")
C_ACCENT = colors.HexColor("#00ff88")
C_ACCENT2 = colors.HexColor("#00bfff")
C_MUTED = colors.HexColor("#8b949e")
C_TEXT = colors.HexColor("#e6edf3")
C_BORDER = colors.HexColor("#30363d")
C_DANGER = colors.HexColor("#ff4444")
C_WARN = colors.HexColor("#ffaa00")

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#ff0033"),
    "HIGH": colors.HexColor("#ff4444"),
    "MEDIUM": colors.HexColor("#ffaa00"),
    "LOW": colors.HexColor("#00ff88"),
    "UNKNOWN": colors.HexColor("#8b949e"),
}

RISK_COLORS = {
    "CRITICAL": colors.HexColor("#ff0033"),
    "HIGH": colors.HexColor("#ff4444"),
    "MEDIUM": colors.HexColor("#ffaa00"),
    "LOW": colors.HexColor("#00ff88"),
}


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", fontName="Courier-Bold", fontSize=22,
                                 textColor=C_ACCENT, spaceAfter=2),
        "subtitle": ParagraphStyle("subtitle", fontName="Courier", fontSize=9,
                                    textColor=C_MUTED, spaceAfter=0),
        "section": ParagraphStyle("section", fontName="Courier-Bold", fontSize=9,
                                   textColor=C_MUTED, spaceBefore=14, spaceAfter=6,
                                   borderPadding=(0, 0, 4, 0)),
        "body": ParagraphStyle("body", fontName="Courier", fontSize=8,
                                textColor=C_TEXT, leading=12),
        "small": ParagraphStyle("small", fontName="Courier", fontSize=7,
                                 textColor=C_MUTED, leading=10),
        "cve_id": ParagraphStyle("cve_id", fontName="Courier-Bold", fontSize=8,
                                  textColor=C_ACCENT2),
        "cve_desc": ParagraphStyle("cve_desc", fontName="Courier", fontSize=7,
                                    textColor=C_MUTED, leading=10),
        "meta_label": ParagraphStyle("meta_label", fontName="Courier-Bold", fontSize=8,
                                      textColor=C_MUTED),
        "meta_value": ParagraphStyle("meta_value", fontName="Courier", fontSize=8,
                                      textColor=C_TEXT),
    }


def _header_table(result: ScanResult, s) -> Table:
    risk_color = RISK_COLORS.get(result.risk_level, C_MUTED)

    left = [
        [Paragraph("VULNSCANNER", s["title"])],
        [Paragraph("Vulnerability Assessment Report", s["subtitle"])],
        [Spacer(1, 6)],
        [Paragraph(f"Target: {escape(str(result.target))} ({escape(str(result.ip))})", s["meta_value"])],
        [Paragraph(f"Hostname: {escape(str(result.hostname))}", s["meta_value"])],
        [Paragraph(f"Scan Time: {escape(str(result.scan_time))}", s["meta_value"])],
    ]
    right = [
        [Paragraph("RISK LEVEL", s["meta_label"])],
        [Paragraph(escape(str(result.risk_level)), ParagraphStyle("rl", fontName="Courier-Bold",
                                                      fontSize=28, textColor=risk_color))],
        [Spacer(1, 6)],
        [Paragraph(f"Open Ports: {result.total_open}", s["meta_value"])],
        [Paragraph(f"CVEs Found: {result.total_cves}", s["meta_value"])],
    ]

    from reportlab.platypus import Table as RLTable
    left_t = RLTable([[row[0]] for row in left], colWidths=[90*mm])
    left_t.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP")]))

    right_t = RLTable([[row[0]] for row in right], colWidths=[60*mm])
    right_t.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ALIGN", (0,0), (-1,-1), "RIGHT"),
    ]))

    wrapper = RLTable([[left_t, right_t]], colWidths=[100*mm, 70*mm])
    wrapper.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
        ("ROUNDEDCORNERS", [6]),
        ("LEFTPADDING", (0,0), (-1,-1), 12),
        ("RIGHTPADDING", (0,0), (-1,-1), 12),
        ("TOPPADDING", (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
    ]))
    return wrapper


def _services_table(services, s) -> list:
    elements = []
    elements.append(Paragraph("DETECTED SERVICES", s["section"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    elements.append(Spacer(1, 6))

    if not services:
        elements.append(Paragraph("No open ports found.", s["small"]))
        return elements

    headers = ["PORT", "PROTOCOL", "SERVICE", "PRODUCT / VERSION", "CVEs"]
    rows = [headers]
    for svc in services:
        ver = " ".join(filter(None, [svc.product, svc.version])) or "—"
        cve_count = str(len(svc.cves)) if svc.cves else "0"
        rows.append([
            str(svc.port),
            escape(str(svc.protocol).upper()),
            escape(str(svc.name)),
            escape(ver),
            cve_count,
        ])

    col_widths = [20*mm, 22*mm, 28*mm, 70*mm, 18*mm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        # Header
        ("BACKGROUND", (0, 0), (-1, 0), C_SURFACE),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_MUTED),
        ("FONTNAME", (0, 0), (-1, 0), "Courier-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),
        ("ALIGN", (0, 0), (-1, 0), "LEFT"),
        # Body
        ("FONTNAME", (0, 1), (-1, -1), "Courier"),
        ("FONTSIZE", (0, 1), (-1, -1), 7.5),
        ("TEXTCOLOR", (0, 1), (-1, -1), C_TEXT),
        ("TEXTCOLOR", (0, 1), (0, -1), C_ACCENT2),   # port col
        ("TEXTCOLOR", (2, 1), (2, -1), C_ACCENT),    # service col
        ("TEXTCOLOR", (4, 1), (4, -1), C_WARN),      # CVE count col
        # Grid
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_SURFACE]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(t)
    return elements


def _cve_section(services, s) -> list:
    elements = []
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("CVE DETAILS", s["section"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    elements.append(Spacer(1, 6))

    all_cves = []
    for svc in services:
        for cve in svc.cves:
            all_cves.append((svc, cve))

    if not all_cves:
        elements.append(Paragraph("No CVEs found for detected services.", s["small"]))
        return elements

    all_cves.sort(key=lambda x: x[1].get("cvss_score") or 0, reverse=True)

    for svc, cve in all_cves:
        sev = cve.get("severity", "UNKNOWN")
        sev_color = SEVERITY_COLORS.get(sev, C_MUTED)
        score = cve.get("cvss_score")
        score_str = f"CVSS {score}" if score else "No score"

        row_left = [
            Paragraph(escape(str(cve["id"])), s["cve_id"]),
            Spacer(1, 3),
            Paragraph(escape(str(cve["description"])), s["cve_desc"]),
            Spacer(1, 3),
            Paragraph(f"Port {svc.port}/{svc.protocol} — {svc.name} {svc.product} {svc.version}", s["small"]),
            Paragraph(escape(str(cve["url"])), s["small"]),
        ]
        row_right = [
            Paragraph(escape(str(sev)), ParagraphStyle("sev", fontName="Courier-Bold",
                                           fontSize=8, textColor=sev_color, alignment=TA_RIGHT)),
            Paragraph(score_str, ParagraphStyle("sc", fontName="Courier",
                                                 fontSize=7, textColor=sev_color, alignment=TA_RIGHT)),
        ]

        left_t = Table([[item] for item in row_left], colWidths=[120*mm])
        left_t.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP")]))

        right_t = Table([[item] for item in row_right], colWidths=[40*mm])
        right_t.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP")]))

        card = Table([[left_t, right_t]], colWidths=[124*mm, 42*mm])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_SURFACE),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEBEFORE", (0, 0), (0, -1), 3, sev_color),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        elements.append(KeepTogether([card, Spacer(1, 5)]))

    return elements


def generate_pdf(result: ScanResult, output_path: str) -> str:
    """Generate PDF report and write to file. Returns the path."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    s = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18*mm,
        rightMargin=18*mm,
        topMargin=16*mm,
        bottomMargin=16*mm,
        title=f"VulnScanner Report — {result.target}",
        author="VulnScanner v1.0",
    )

    # Dark background on every page
    def dark_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        # Footer
        canvas.setFont("Courier", 7)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(18*mm, 10*mm,
                          f"VulnScanner — For authorized testing only | Report: {result.scan_time}")
        canvas.drawRightString(A4[0] - 18*mm, 10*mm, f"Page {doc.page}")
        canvas.restoreState()

    story = []
    story.append(_header_table(result, s))
    story.append(Spacer(1, 14))
    story.extend(_services_table(result.services, s))
    story.extend(_cve_section(result.services, s))

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)
    return output_path
