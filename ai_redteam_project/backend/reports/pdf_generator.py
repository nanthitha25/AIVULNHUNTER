from reportlab.pdfgen import canvas

def generate_pdf(report):
    c = canvas.Canvas("final_report.pdf")
    y = 800
    c.drawString(50, y, "AI Vulnerability Scan Report")
    y -= 40

    for k, v in report.items():
        c.drawString(50, y, f"{k}: {v['status']}")
        y -= 20
        c.drawString(70, y, f"Mitigation: {v['mitigation']}")
        y -= 30

    c.save()

