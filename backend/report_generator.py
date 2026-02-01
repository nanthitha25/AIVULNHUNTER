from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from datetime import datetime

def generate_report(scan_result, output="report.pdf"):
    """Generate a comprehensive PDF report from scan results.
    
    Args:
        scan_result: Dictionary containing scan results with:
            - target: Target info (dict or string)
            - rules_applied: List of rules used
            - vulnerabilities: List of found vulnerabilities
            - explainable_ai: Detailed AI analysis
        output: Output filename for the PDF
    """
    doc = SimpleDocTemplate(output, pagesize=A4)
    styles = getSampleStyleSheet()
    content = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.darkblue,
        spaceAfter=30
    )
    
    section_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.darkgreen,
        spaceBefore=20,
        spaceAfter=10
    )
    
    subsection_style = ParagraphStyle(
        'SubsectionTitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.darkred,
        spaceBefore=15,
        spaceAfter=8
    )
    
    normal_style = ParagraphStyle(
        'NormalText',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=5
    )
    
    # ========== HEADER ==========
    content.append(Paragraph("🛡️ AI Vulnerability Assessment Report", title_style))
    content.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    content.append(Spacer(1, 20))

    # ========== 1️⃣ TARGET OVERVIEW ==========
    content.append(Paragraph("1. Target Overview", section_style))
    
    target = scan_result.get('target', {})
    if isinstance(target, dict):
        target_name = target.get('name', target.get('id', 'Unknown'))
        target_type = target.get('type', 'AI System')
        target_desc = target.get('description', 'No description available')
        content.append(Paragraph(f"<b>Target Name:</b> {target_name}", normal_style))
        content.append(Paragraph(f"<b>Type:</b> {target_type}", normal_style))
        content.append(Paragraph(f"<b>Description:</b> {target_desc}", normal_style))
    else:
        content.append(Paragraph(f"<b>Target:</b> {target}", normal_style))
    
    # Scan metadata
    scan_time = scan_result.get('scan_timestamp', datetime.now().isoformat())
    content.append(Paragraph(f"<b>Scan Timestamp:</b> {scan_time}", normal_style))
    content.append(Spacer(1, 15))

    # ========== 2️⃣ RULES APPLIED ==========
    content.append(Paragraph("2. Rules Applied", section_style))
    
    rules_applied = scan_result.get('rules_applied', [])
    if rules_applied:
        # Create rules table
        rules_data = [['Rule ID', 'Name', 'OWASP', 'Severity', 'Priority']]
        for rule in rules_applied:
            rule_id = str(rule.get('id', rule.get('rule_id', 'N/A')))[:8]
            rule_data = [
                rule_id,
                rule.get('name', 'Unknown'),
                rule.get('owasp', 'N/A'),
                rule.get('severity', 'MEDIUM'),
                str(rule.get('priority', 3))
            ]
            rules_data.append(rule_data)
        
        rules_table = Table(rules_data, colWidths=[80, 150, 80, 70, 60])
        rules_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        content.append(rules_table)
    else:
        content.append(Paragraph("No specific rules were applied.", normal_style))
    
    content.append(Spacer(1, 15))

    # ========== 3️⃣ VULNERABILITIES FOUND ==========
    content.append(Paragraph("3. Vulnerabilities Found", section_style))
    
    vulnerabilities = scan_result.get('vulnerabilities', scan_result.get('results', []))
    if vulnerabilities:
        content.append(Paragraph(f"Total vulnerabilities detected: {len(vulnerabilities)}", normal_style))
        content.append(Spacer(1, 10))
        
        for i, vuln in enumerate(vulnerabilities, 1):
            attack_name = vuln.get('attack', vuln.get('name', f'Vulnerability #{i}'))
            severity = vuln.get('severity', 'UNKNOWN').upper()
            priority = vuln.get('priority', vuln.get('rule_priority', 3))
            
            # Severity color indicator
            severity_colors = {
                'CRITICAL': colors.red,
                'HIGH': colors.orange,
                'MEDIUM': colors.yellow,
                'LOW': colors.green
            }
            severity_color = severity_colors.get(severity, colors.grey)
            
            content.append(Paragraph(f"<b>{i}. {attack_name}</b>", subsection_style))
            content.append(Paragraph(f"<b>Severity:</b> <font color='{severity_color}'>{severity}</font> | <b>Priority:</b> {priority}", normal_style))
            content.append(Spacer(1, 5))
            
            # Evidence
            evidence = vuln.get('evidence', vuln.get('details', ''))
            if evidence:
                content.append(Paragraph(f"<b>Evidence:</b> {evidence}", normal_style))
            
            content.append(Spacer(1, 10))
    else:
        content.append(Paragraph("No vulnerabilities were detected.", normal_style))
    
    content.append(Spacer(1, 15))

    # ========== 4️⃣ SEVERITY & PRIORITY SUMMARY ==========
    content.append(Paragraph("4. Severity & Priority Summary", section_style))
    
    # Count by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in vulnerabilities:
        sev = vuln.get('severity', 'MEDIUM').upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Priority distribution
    priority_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for vuln in vulnerabilities:
        pri = vuln.get('priority', vuln.get('rule_priority', 3))
        if pri in priority_counts:
            priority_counts[pri] += 1
    
    # Severity summary table
    severity_data = [['Severity', 'Count', 'Risk Level']]
    for sev, count in severity_counts.items():
        risk = '🔴 Critical' if sev == 'CRITICAL' else ('🟠 High' if sev == 'HIGH' else ('🟡 Medium' if sev == 'MEDIUM' else '🟢 Low'))
        severity_data.append([sev, str(count), risk])
    
    severity_table = Table(severity_data, colWidths=[80, 50, 120])
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgreen),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    content.append(severity_table)
    content.append(Spacer(1, 10))
    
    content.append(Paragraph(f"<b>Priority Distribution:</b>", normal_style))
    for pri, count in sorted(priority_counts.items()):
        if count > 0:
            content.append(Paragraph(f"  Priority {pri}: {count} items", normal_style))
    
    content.append(Spacer(1, 15))

    # ========== 5️⃣ MITIGATION STEPS ==========
    content.append(Paragraph("5. Mitigation Steps", section_style))
    
    mitigations = scan_result.get('mitigations', [])
    if mitigations:
        for i, mit in enumerate(mitigations, 1):
            rule_name = mit.get('rule_name', mit.get('attack', f'Mitigation #{i}'))
            steps = mit.get('mitigation', mit.get('steps', 'No specific steps provided'))
            
            content.append(Paragraph(f"<b>{i}. {rule_name}</b>", subsection_style))
            
            # Handle multi-line mitigation steps
            if isinstance(steps, str):
                steps_list = steps.split('. ')
                for step in steps_list:
                    if step.strip():
                        content.append(Paragraph(f"• {step.strip()}", normal_style))
            else:
                content.append(Paragraph(str(steps), normal_style))
            
            content.append(Spacer(1, 10))
    else:
        # Extract mitigations from vulnerabilities
        for vuln in vulnerabilities:
            mitigation = vuln.get('mitigation', '')
            if mitigation:
                attack_name = vuln.get('attack', 'Vulnerability')
                content.append(Paragraph(f"<b>{attack_name}:</b>", subsection_style))
                content.append(Paragraph(f"• {mitigation}", normal_style))
                content.append(Spacer(1, 8))
    
    content.append(Spacer(1, 15))

    # ========== 6️⃣ EXPLAINABLE AI SUMMARY ==========
    content.append(Paragraph("6. Explainable AI Summary", section_style))
    
    explainable_ai = scan_result.get('explainable_ai', [])
    if explainable_ai:
        content.append(Paragraph("The AI analysis identified the following patterns:", normal_style))
        content.append(Spacer(1, 8))
        
        for i, analysis in enumerate(explainable_ai, 1):
            attack = analysis.get('attack', f'Analysis #{i}')
            why = analysis.get('why', 'Analysis details not available')
            confidence = analysis.get('confidence', analysis.get('score', 0))
            
            content.append(Paragraph(f"<b>{i}. {attack}</b>", subsection_style))
            content.append(Paragraph(f"<b>Analysis:</b> {why}", normal_style))
            content.append(Paragraph(f"<b>Confidence Score:</b> {confidence:.2%}" if isinstance(confidence, float) else f"<b>Score:</b> {confidence}", normal_style))
            content.append(Spacer(1, 8))
    else:
        content.append(Paragraph("The AI analysis completed without detailed explanations.", normal_style))
        content.append(Paragraph("The scan detected patterns consistent with security vulnerabilities in AI systems.", normal_style))
    
    content.append(Spacer(1, 20))

    # ========== FOOTER ==========
    content.append(Paragraph("─" * 50, normal_style))
    content.append(Paragraph("Report generated by AivulnHunter - AI Red Team Security Scanner", normal_style))
    content.append(Paragraph("This report is for authorized security testing purposes only.", normal_style))

    # Build PDF
    doc.build(content)
    return output

