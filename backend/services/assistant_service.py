import os
import google.generativeai as genai
from services.rag_service import search_rules, get_scan_results

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-pro")

SYSTEM_PROMPT = """
You are AIVulnHunter Security Assistant.

You help users understand:
- AI vulnerabilities
- OWASP rules
- Scan results
- Mitigation strategies

You must:
- Explain clearly
- Be beginner friendly
- Provide mitigation

You must NOT:
- Provide hacking steps
"""

def build_context(user_message, scan_id=None):

    context = ""

    # 🔍 Search rules
    rules = search_rules(user_message)

    if rules:
        context += "Relevant Security Rules:\n"
        for r in rules:
            context += f"""
Name: {r[0]}
Severity: {r[3]}
Description: {r[1]}
Mitigation: {r[2]}
"""

    # 📊 Scan results
    if scan_id:
        scan_results = get_scan_results(scan_id)

        if scan_results:
            context += "\nScan Findings:\n"
            for s in scan_results:
                context += f"""
Vulnerability: {s[0]}
Severity: {s[1]}
Details: {s[2]}
"""

    return context


def ask_gemini(user_message, scan_id=None):

    context = build_context(user_message, scan_id)

    prompt = f"""
{SYSTEM_PROMPT}

Context:
{context}

User Question:
{user_message}
"""

    response = model.generate_content(prompt)

    return response.text
