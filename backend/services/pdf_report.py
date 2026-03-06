"""
PDF Report Generator - Enhanced with full OWASP mapping, risk scores, and mitigations

Generates a professionally formatted PDF vulnerability assessment report
using ReportLab, matching the layout requested by the user.
"""

import uuid
import os
from pathlib import Path
from typing import List, Dict

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)

# Report output directory (relative to project root)
REPORT_DIR = Path(__file__).resolve().parent.parent.parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

# ------------------------------------------------------------------ #
# Colour palette                                                       #
# ------------------------------------------------------------------ #
ST_COLORS = {
    "CRITICAL": colors.HexColor("#b91c1c"), # Dark Red
    "HIGH":     colors.HexColor("#eab308"), # Yellow/Orange
    "MEDIUM":   colors.HexColor("#3b82f6"), # Blue
    "LOW":      colors.HexColor("#22c55e"), # Green
}

# ------------------------------------------------------------------ #
# Style helpers                                                         #
# ------------------------------------------------------------------ #

def _styles():
    base = getSampleStyleSheet()
    styles = {
        "report_title": ParagraphStyle(
            "ReportTitle", fontName="Helvetica-Bold", fontSize=18,
            textColor=colors.black, alignment=TA_LEFT, spaceAfter=20, spaceBefore=40
        ),
        "target_info": ParagraphStyle(
            "TargetInfo", fontName="Helvetica", fontSize=9,
            textColor=colors.black, alignment=TA_LEFT, spaceAfter=5, leading=12
        ),
        "section_header": ParagraphStyle(
            "SectionHeader", fontName="Helvetica-Bold", fontSize=14,
            textColor=colors.black, alignment=TA_LEFT, spaceBefore=25, spaceAfter=15
        ),
        "subsection_header": ParagraphStyle(
            "SubSectionHeader", fontName="Helvetica-BoldOblique", fontSize=11,
            textColor=colors.black, alignment=TA_LEFT, spaceBefore=15, spaceAfter=5
        ),
        "body_text": ParagraphStyle(
            "BodyText", fontName="Helvetica", fontSize=9,
            textColor=colors.black, alignment=TA_LEFT, spaceAfter=4, leading=12
        ),
        "finding_title": ParagraphStyle(
            "FindingTitle", fontName="Helvetica-Bold", fontSize=11,
            textColor=colors.black, alignment=TA_LEFT, spaceBefore=25, spaceAfter=10
        ),
        "finding_meta": ParagraphStyle(
            "FindingMeta", fontName="Helvetica-Bold", fontSize=9,
            textColor=colors.black, alignment=TA_LEFT, spaceBefore=2, spaceAfter=2, leading=12
        ),
        "finding_label": ParagraphStyle(
            "FindingLabel", fontName="Helvetica-Bold", fontSize=10,
            textColor=colors.black, alignment=TA_LEFT, spaceBefore=15, spaceAfter=5
        ),
        "evidence_text": ParagraphStyle(
            "EvidenceText", fontName="Helvetica", fontSize=8,
            textColor=colors.gray, alignment=TA_LEFT, spaceAfter=5, leading=10
        ),
    }
    return styles

def _wrapped(text: str, style) -> Paragraph:
    safe = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(safe, style)

def _html_wrapped(text: str, style) -> Paragraph:
    return Paragraph(text, style)

# ------------------------------------------------------------------ #
# Main report generator                                                 #
# ------------------------------------------------------------------ #

def generate_pdf_report(scan_result: dict) -> str:
    """
    Generate a PDF vulnerability assessment report.
    """
    filename = f"aivulnhunter_report_{uuid.uuid4().hex[:8]}.pdf"
    output_path = REPORT_DIR / filename

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=2.5*cm, rightMargin=2.5*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    story = []
    ST = _styles()

    target      = scan_result.get("target", "N/A")
    target_type = scan_result.get("target_type", scan_result.get("scan_type", "UNKNOWN"))
    scan_id     = scan_result.get("scan_id", "N/A")
    results     = scan_result.get("results", [])
    risk_sum    = scan_result.get("risk_summary", {})

    vuln_results = [r for r in results if r.get("status") == "VULNERABLE"]
    risk_rating  = risk_sum.get("risk_rating", _calculate_rating(results))
    overall_risk = risk_sum.get("overall_risk_score", _total_risk(results))
    score_out_of_100 = max(0, 100 - overall_risk) # Assuming 100 is secure, subtract risk

    # Count distribution
    distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in vuln_results:
        sev = r.get("severity", "MEDIUM").upper()
        if sev in distribution:
            distribution[sev] += 1

    # Date
    from datetime import datetime
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ------------------- Title Page Content ------------------- #
    story.append(_wrapped("AivulnHunter Security Assessment Report", ST["report_title"]))
    
    # Target Info
    story.append(_html_wrapped(f"<b>Target:</b> {target}", ST["target_info"]))
    story.append(_html_wrapped(f"<b>Scan Date:</b> {scan_date}", ST["target_info"]))
    
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", color=colors.gray, thickness=0.5))
    story.append(Spacer(1, 0.5*cm))

    # ------------------- Executive Summary ------------------- #
    story.append(_wrapped("Executive Summary", ST["section_header"]))
    
    story.append(_wrapped("The AIvulnHunter security assessment was conducted to evaluate potential vulnerabilities in the target application. The system was tested using automated adversarial testing techniques aligned with OWASP security guidelines.", ST["body_text"]))
    story.append(Spacer(1, 0.2*cm))
    
    # Security Posture Overview
    story.append(_wrapped("Security Posture Overview", ST["subsection_header"]))
    story.append(_html_wrapped(f"Overall Security Score: <b>{score_out_of_100:.0f} / 100</b>", ST["body_text"]))
    story.append(_html_wrapped(f"Security Posture: <b>{risk_rating} RISK</b>", ST["body_text"]))
    story.append(_html_wrapped(f"AI Risk Index: <b>{len(vuln_results)} vulnerabilities detected</b>", ST["body_text"]))

    # Risk Distribution
    story.append(_wrapped("Risk Distribution", ST["subsection_header"]))
    story.append(_html_wrapped(f"Critical: {distribution['CRITICAL']}", ST["body_text"]))
    story.append(_html_wrapped(f"High: {distribution['HIGH']}", ST["body_text"]))
    story.append(_html_wrapped(f"Medium: {distribution['MEDIUM']}", ST["body_text"]))
    story.append(Spacer(1, 0.5*cm))
    
    story.append(_wrapped(f"A total of {len(vuln_results)} vulnerability(ies) were identified during the assessment.", ST["body_text"]))
    
    # Optional pagebreak for cleaner looks
    story.append(Spacer(1, 1*cm))

    # ------------------- Detailed Findings ------------------- #
    story.append(_wrapped("Detailed Findings", ST["section_header"]))

    if not vuln_results:
        story.append(_wrapped("No vulnerabilities detected. The target appears secure against the tested attack vectors.", ST["body_text"]))
    else:
        for idx, r in enumerate(vuln_results, 1):
            sev = r.get("severity", "MEDIUM").upper()
            confidence = r.get("confidence", 0.0)
            color_hex = ST_COLORS.get(sev, colors.black).hexval() # Get hex for HTML
            color_str = f"#{hex(color_hex)[2:].zfill(6)}"

            # Title
            story.append(_wrapped(f"{idx}. {r.get('name', r.get('rule_id', 'Unknown Vulnerability'))}", ST["finding_title"]))
            
            # Meta tags
            story.append(_html_wrapped(f"<b>Severity:</b> <font color='{color_str}'>{sev}</font>", ST["finding_meta"]))
            story.append(_html_wrapped(f"<b>Confidence:</b> {confidence * 100:.0f}%", ST["finding_meta"]))
            story.append(_html_wrapped(f"<b>OWASP Classification:</b> {r.get('owasp', 'General')} – {r.get('name', '')}", ST["finding_meta"]))
            
            # Risk Overview
            story.append(_wrapped("Risk Overview", ST["finding_label"]))
            story.append(_wrapped(r.get("explanation", "The target demonstrated behavior consistent with this vulnerability class."), ST["body_text"]))
            
            # Evidence
            story.append(_wrapped("Evidence", ST["finding_label"]))
            evidence_text = str(r.get("evidence", "Behavioral confirmation without specific payload echoing."))
            for line in evidence_text.split("\n"):
                if line.strip():
                    story.append(_wrapped(line.strip(), ST["evidence_text"]))
            
            # Mitigation
            story.append(_wrapped("Recommended Mitigation", ST["finding_label"]))
            mitigation_text = str(r.get("mitigation", "Implement standard security best practices for this finding."))
            for line in mitigation_text.split("\n"):
                if line.strip():
                    story.append(_wrapped(line.strip(), ST["body_text"]))
            
            # Separator per finding
            story.append(Spacer(1, 1*cm))
            story.append(HRFlowable(width="100%", color=colors.whitesmoke, thickness=1))
            story.append(Spacer(1, 0.5*cm))

    # Build the PDF
    doc.build(story)
    return str(output_path)

def _calculate_rating(results: list) -> str:
    total = sum(r.get("risk_score", 0) for r in results)
    if total >= 200: return "CRITICAL"
    if total >= 100: return "HIGH"
    if total >= 50:  return "MEDIUM"
    return "LOW"

def _total_risk(results: list) -> float:
    return round(sum(r.get("risk_score", 0) for r in results), 2)
