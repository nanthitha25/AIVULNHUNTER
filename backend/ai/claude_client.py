import anthropic
import os
from dotenv import load_dotenv

# Ensure .env is loaded
load_dotenv()

def ask_claude(system_prompt, user_prompt):
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY missing")
        raise RuntimeError("ANTHROPIC_API_KEY not configured")

    client = anthropic.Anthropic(api_key=api_key)
    
    print("Calling Claude Sonnet 3.5...")
    response = client.messages.create(
        model="claude-3-5-sonnet-20240620",
        system=system_prompt,
        max_tokens=1024,
        messages=[{"role": "user", "content": user_prompt}]
    )

    return response.content[0].text
