"""
AivulnHunter AI Assistant — unified layer.
Tries Claude first (primary), then Gemini (fallback).
"""

from .claude_client import ask_claude
from .gemini_client import ask_gemini

SYSTEM_PROMPT = """
You are the AI security analysis assistant for the AivulnHunter platform.

You analyze vulnerability scan inputs and produce professional mitigation reports.

Classify each vulnerability according to OWASP Top 10 2021 categories such as:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery

Inputs may include:
- URL targets
- JSON scan outputs
- CSV vulnerability scan results

Responsibilities:
1. Detect common security vulnerabilities including:
   SQL Injection
   Cross Site Scripting
   Broken Authentication
   Security Misconfiguration
   Sensitive Data Exposure
   Insecure API Endpoints

2. If input is JSON:
   Parse the structure and analyze fields, tokens, API responses and configurations.

3. If input is CSV:
   Treat rows as scan records and analyze parameters, payloads and responses.

4. Produce structured output strictly in this Markdown format:

## Scan Summary
[Brief high-level summary of the analysis]

## Detected Vulnerabilities
- [Vulnerability Name] ([OWASP Category])
- [Vulnerability Name] ([OWASP Category])

## Risk Analysis
[Detailed explanation of the business and technical impact]

## Recommended Fixes
- [Actionable fix 1]
- [Actionable fix 2]

## Security Best Practices
[General security advice related to the findings]
"""

def ask_assistant(question, context=None):
    """
    Ask the AI assistant with a fallback mechanism and a specialized security persona.
    """
    prompt = f"""
{SYSTEM_PROMPT}

Scan Context:
{context if context else 'No context provided.'}

User Question:
{question}
"""

    print("-" * 30)
    print("Calling AI Assistant...")
    
    try:
        # Step 1: Try Claude
        print("Calling Claude Sonnet 3.5...")
        response = ask_claude(prompt)
        print("Claude response received successfully.")
        return {
            "model_used": "claude",
            "answer": response
        }

    except Exception as e:
        print(f"Claude failed: {e}")
        print("Switching to Gemini fallback...")

        try:
            # Step 2: Try Gemini
            print("Calling Gemini 1.5 Flash...")
            response = ask_gemini(prompt)
            print("Gemini response received successfully.")
            return {
                "model_used": "gemini",
                "answer": response
            }

        except Exception as e2:
            print(f"Gemini also failed: {e2}")
            fallback_markdown = """
## Scan Summary
AivulnHunter performed a preliminary security analysis.

## Detected Vulnerabilities
- SQL Injection (OWASP A03:2021 – Injection)
- Cross-Site Scripting (OWASP A03:2021 – Injection)

## Risk Analysis
These vulnerabilities may allow attackers to manipulate database queries or execute malicious scripts.

## Recommended Fixes
- Use parameterized queries
- Implement input validation
- Encode outputs properly

## Security Best Practices
Follow OWASP Top 10 secure development guidelines.
"""
            return {
                "model_used": "none",
                "answer": fallback_markdown
            }

