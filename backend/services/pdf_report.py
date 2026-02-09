from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import uuid

def generate_pdf_report(scan_result: dict):
    filename = f"scan_report_{uuid.uuid4()}.pdf"
    path = f"reports/{filename}"

    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4

    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "AI Vulnerability Scan Report")

    y -= 40
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Target: {scan_result['target']}")

    y -= 30
    for r in scan_result["results"]:
        c.drawString(50, y, f"Rule: {r['name']} ({r['owasp']})")
        y -= 15
        c.drawString(70, y, f"Status: {r['status']}")
        y -= 15
        c.drawString(70, y, f"Explanation: {r['explanation']}")
        y -= 15
        c.drawString(70, y, f"Mitigation: {r['mitigation']}")
        y -= 30

        if y < 100:
            c.showPage()
            y = height - 50

    c.save()
    return path

