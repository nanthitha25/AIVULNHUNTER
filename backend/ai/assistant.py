"""
AivulnHunter AI Assistant — unified layer.
Tries Claude first (primary), then Gemini (fallback).
"""

from .claude_client import ask_claude
from .gemini_client import ask_gemini

SYSTEM_PROMPT = """You are the AivulnHunter AI Security Assistant.

Your role is to explain cybersecurity vulnerabilities clearly, accurately, and contextually based on the user's question.

CRITICAL BEHAVIOR RULES:

1. ALWAYS answer the USER'S QUESTION directly.
   - Do NOT give generic scan summaries unless explicitly asked.
   - Do NOT list unrelated vulnerabilities.

2. RESPONSE STRUCTURE (MANDATORY):

For any vulnerability explanation, follow this format:

🔍 Definition  
Explain what the vulnerability is in simple terms.

⚠️ Why it is dangerous  
Explain the real-world risk.

💣 Real-world example  
Give a practical example (API, LLM, or AI agent context).

🛡️ How to fix it  
Provide actionable mitigation steps.

(Optional)
📌 In AivulnHunter context  
Explain how AivulnHunter detects it (if relevant).

---

3. CONTEXT AWARENESS

If user asks:
- "Explain prompt injection" -> Explain ONLY prompt injection
- "Explain BOLA" -> Explain ONLY BOLA
- "Explain this scan result" -> THEN use scan data

DO NOT mix multiple vulnerabilities unless asked.

---

4. SECURITY DOMAIN FOCUS

You specialize in:
- OWASP API Top 10
- OWASP LLM Top 10
- AI Agent vulnerabilities

---

5. RESPONSE STYLE

- Professional but easy to understand
- No unnecessary verbosity
- No generic filler text
- No hallucinated vulnerabilities

---

6. STRICT RESTRICTIONS

❌ DO NOT:
- Return "Scan Summary" unless user asks
- Mention SQL Injection or XSS unless relevant
- Give unrelated vulnerabilities
"""

def ask_assistant(question, context=None):
    """
    Ask the AI assistant with a fallback mechanism and a specialized security persona.
    """
    if "explain" in question.lower():
        mode = "explanation"
    elif "scan" in question.lower():
        mode = "analysis"
    else:
        mode = "explanation" # default

    user_prompt = f"""User Query: {question}

Mode: {mode}

If mode is explanation -> explain concept only.
If mode is analysis -> use scan data.

Scan Context (for analysis mode only):
{context if context else 'No context provided.'}
"""

    print("-" * 30)
    print("Calling AI Assistant...")
    
    try:
        # Step 1: Try Claude
        print("Calling Claude Sonnet 3.5...")
        response = ask_claude(SYSTEM_PROMPT, user_prompt)
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
            response = ask_gemini(SYSTEM_PROMPT, user_prompt)
            print("Gemini response received successfully.")
            return {
                "model_used": "gemini",
                "answer": response
            }

        except Exception as e2:
            print(f"Gemini also failed: {e2}")
            fallback_markdown = """
🔍 Definition
Fallback response: Unable to contact AI services. 
Please ensure API keys are configured and services are online.

⚠️ Why it is dangerous
Without AI context, detailed vulnerability explanations cannot be fetched dynamically.

💣 Real-world example
N/A

🛡️ How to fix it
Check configuration keys for Anthropic and Gemini.
"""
            return {
                "model_used": "none",
                "answer": fallback_markdown
            }
