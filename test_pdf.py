from backend.services.pdf_report import generate_pdf_report
import os

scan_data = {
    "target": "http://localhost:8000/v1/user/profile",
    "results": [
        {
            "name": "SQL Injection",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "explanation": "A SQL injection vulnerability was found in the id parameter.",
            "mitigation": "Use parameterized queries.",
            "evidence": "Payload: ' OR 1=1 --\nResult: 500 Internal Server Error\n" + "x" * 200 + "\n" + "-" * 150 # long string
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "confidence": 0.85,
            "explanation": "Stored XSS was found in the user bio.",
            "mitigation": "Sanitize user input before storing in the database.",
            "evidence": "<script>alert(1)</script>" + "A" * 150
        },
        {
            "name": "Insecure Direct Object Reference",
            "severity": "MEDIUM",
            "confidence": 0.55,
            "explanation": "User ID can be changed to access other user profiles.",
            "mitigation": "Validate user authorization on the backend.",
            "evidence": "Request to /api/users/999 returned HTTP 200 OK."
        }        
    ]
}

if __name__ == "__main__":
    report_path = generate_pdf_report(scan_data)
    print(f"Generated PDF: {report_path}")
    print("Test completed successfully.")
