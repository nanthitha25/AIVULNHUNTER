import os
import time
from dotenv import load_dotenv
from google import genai

from services.rag_service import search_rules, get_scan_results

load_dotenv()

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

RESPONSE_CACHE = {}
LAST_CALL = 0

def rate_limiter():
    global LAST_CALL
    now = time.time()
    if now - LAST_CALL < 1:
        time.sleep(1 - (now - LAST_CALL))
    LAST_CALL = time.time()

def build_context(user_message, scan_id=None):
    context = ""
    # 🔍 Search rules (RAG)
    try:
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
    except Exception as e:
        print(f"RAG rule search failed: {e}")

    # 📊 Scan results integration
    if scan_id:
        try:
            scan_results = get_scan_results(scan_id)
            if scan_results:
                context += "\nScan Findings for context:\n"
                for s in scan_results:
                    context += f"""
Vulnerability: {s[0]}
Severity: {s[1]}
Details: {s[2]}
"""
        except Exception as e:
            print(f"Scan result context retrieval failed: {e}")

    return context

def generate_with_retry(prompt):
    for attempt in range(3):
        try:
            rate_limiter()
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
                config={
                    "temperature": 0.3,
                    "max_output_tokens": 500
                }
            )
            return response.text
        except Exception as e:
            print(f"Gemini API attempt {attempt} failed: {e}")
            time.sleep(2 ** attempt)

    return "AI service temporarily unavailable."

def ask_assistant(query, scan_id=None):
    cache_key = f"{scan_id}:{query}"
    if cache_key in RESPONSE_CACHE:
        return RESPONSE_CACHE[cache_key]

    context = build_context(query, scan_id)

    prompt = f"""
You are the AI security assistant for AI-VulnHunter.

Context:
{context}

User Question:
{query}

Security Copilot Prompt Mode:
Instead of just explaining rules, output your response exactly in this format:

1️⃣ Vulnerability Explanation
2️⃣ Attack Example
3️⃣ Detection Logic
4️⃣ Secure Fix
5️⃣ Confidence Score

Example output:

Vulnerability: Token Passthrough
Attack:
An attacker forwards a stolen token to another microservice.
Detection:
Check if the token audience matches the service.
Fix:
Validate token issuer and audience before forwarding.
Confidence: 92%
"""

    answer = generate_with_retry(prompt)
    RESPONSE_CACHE[cache_key] = answer
    return answer

# Legacy name for compatibility
def ask_gemini(user_message, scan_id=None):
    return ask_assistant(user_message, scan_id)
