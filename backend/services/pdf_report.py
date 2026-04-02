from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    ListFlowable,
    ListItem
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import A4
from reportlab.platypus import HRFlowable
from datetime import datetime
from pathlib import Path
import os


REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


def generate_pdf_report(scan_data: dict) -> str:
    """
    Generates a structured professional vulnerability assessment PDF.
    """

    filename = f"scan_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=60,
        bottomMargin=40
    )

    elements = []
    styles = getSampleStyleSheet()

    # Custom styles
    header_style = styles["Heading1"]
    section_style = styles["Heading2"]
    normal_style = styles["BodyText"]

    bold_style = ParagraphStyle(
        name="BoldStyle",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=11
    )

    small_style = ParagraphStyle(
        name="SmallStyle",
        parent=styles["BodyText"],
        fontSize=8,
        textColor=colors.grey,
        wordWrap='CJK'
    )

    # ----------------------------
    # Title Section
    # ----------------------------
    elements.append(Paragraph("AivulnHunter Security Assessment Report", header_style))
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph(f"<b>Target:</b> {scan_data.get('target')}", normal_style))
    elements.append(Paragraph(f"<b>Scan Date:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", normal_style))
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    elements.append(Spacer(1, 0.3 * inch))

    vulnerabilities = scan_data.get("results", [])

    if not vulnerabilities:
        elements.append(Paragraph("<b>Security Posture Assessment</b>", styles["Heading2"]))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("""
        The assessment did not identify any exploitable vulnerabilities 
        based on the executed rule set.<br/><br/>
        
        The system appears to enforce:<br/>
        • Proper access control validation<br/>
        • Input sanitization mechanisms<br/>
        • Tool execution safeguards<br/>
        • Output filtering controls<br/><br/>
        
        However, absence of detected vulnerabilities does not guarantee 
        complete security. Continuous monitoring and periodic assessments 
        are strongly recommended.
        """, normal_style))
    else:
        elements.append(Paragraph("Executive Summary", section_style))
        elements.append(Spacer(1, 0.2 * inch))

        critical = sum(1 for f in vulnerabilities if f.get("severity") == "CRITICAL")
        high = sum(1 for f in vulnerabilities if f.get("severity") == "HIGH")
        medium = sum(1 for f in vulnerabilities if f.get("severity") == "MEDIUM")

        # CISO Score Calculation
        score = 100 - (critical * 20) - (high * 10) - (medium * 5)
        score = max(0, score)

        if critical > 0:
            posture = "CRITICAL RISK"
        elif high > 0:
            posture = "ELEVATED RISK"
        elif medium > 0:
            posture = "MODERATE RISK"
        else:
            posture = "LOW RISK"

        # AI-Native Risk Index
        ai_risk_count = sum(1 for f in vulnerabilities if str(f.get("owasp", "")).startswith(("LLM", "AGENT")))

        elements.append(Paragraph("<b>Security Posture Overview</b>", styles["Heading3"]))
        elements.append(Paragraph(f"""
        Overall Security Score: <b>{score} / 100</b><br/>
        Security Posture: <b>{posture}</b><br/>
        AI Risk Index: <b>{ai_risk_count} AI-native vulnerabilities detected</b>
        """, normal_style))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("<b>Risk Distribution</b>", styles["Heading3"]))
        elements.append(Paragraph(f"""
        Critical: {critical}<br/>
        High: {high}<br/>
        Medium: {medium}<br/>
        """, normal_style))
        elements.append(Spacer(1, 12))

        elements.append(
            Paragraph(
                f"A total of <b>{len(vulnerabilities)}</b> vulnerability(ies) were identified during the assessment.",
                normal_style,
            )
        )

        elements.append(Spacer(1, 0.4 * inch))

        # ----------------------------
        # Detailed Findings
        # ----------------------------
        elements.append(Paragraph("Detailed Findings", section_style))
        elements.append(Spacer(1, 0.3 * inch))

        for idx, vuln in enumerate(vulnerabilities, 1):

            elements.append(
                Paragraph(
                    f"<b>{idx}. {vuln.get('name')}</b>",
                    bold_style
                )
            )

            elements.append(Spacer(1, 0.1 * inch))

            severity = str(vuln.get('severity', 'UNKNOWN')).upper()
            sev_color = "black"
            if severity == "CRITICAL":
                sev_color = "red"
            elif severity == "HIGH":
                sev_color = "orange"
            elif severity == "MEDIUM":
                sev_color = "#fcdb03"
            elif severity == "LOW":
                sev_color = "green"

            elements.append(
                Paragraph(
                    f"<b>Severity:</b> <font color='{sev_color}'>{severity}</font><br/>"
                    f"<b>Confidence:</b> {int(vuln.get('confidence', 0) * 100)}%",
                    normal_style
                )
            )

            # OWASP Classification
            elements.append(
                Paragraph(
                    f"<b>OWASP Classification:</b> {vuln.get('owasp', 'Unknown')} – {vuln.get('name', 'N/A')}",
                    normal_style
                )
            )
            elements.append(Spacer(1, 12))

            # Risk Overview
            elements.append(Paragraph("<b>Risk Overview</b>", bold_style))
            elements.append(
                Paragraph(
                    vuln.get("explanation", "No description available.").replace("\n", "<br/>"),
                    normal_style
                )
            )

            elements.append(Spacer(1, 0.2 * inch))

            # Technical Impact
            if vuln.get("technical_impact"):
                elements.append(Paragraph("<b>Technical Impact</b>", styles["Heading3"]))
                elements.append(Paragraph(vuln.get("technical_impact", "").replace("\n", "<br/>"), normal_style))
                elements.append(Spacer(1, 12))

            # Evidence
            elements.append(Paragraph("<b>Evidence</b>", bold_style))
            # Replace newlines with <br/> for ReportLab to render correctly
            evidence_text = str(vuln.get("evidence", "No evidence provided."))
            evidence_text = evidence_text.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")

            elements.append(
                Paragraph(
                    evidence_text,
                    small_style
                )
            )

            elements.append(Spacer(1, 0.2 * inch))

            # Mitigation
            elements.append(Paragraph("<b>Recommended Mitigation</b>", bold_style))
            elements.append(
                Paragraph(
                    vuln.get("mitigation", "No mitigation guidance available."),
                    normal_style
                )
            )

            elements.append(Spacer(1, 0.4 * inch))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
            elements.append(Spacer(1, 0.4 * inch))

    doc.build(elements)

    return str(filepath)
