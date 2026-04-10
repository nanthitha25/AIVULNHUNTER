import anthropic
import os
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

try:
    print("Testing Claude...")
    response = client.messages.create(
        model="claude-3-5-sonnet-20240620",
        max_tokens=10,
        messages=[{"role": "user", "content": "Hello"}]
    )
    print(f"Success: {response.content[0].text}")
except Exception as e:
    print(f"Failure: {e}")
