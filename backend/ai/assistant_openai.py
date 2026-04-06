from openai import OpenAI
from ..config import OPENAI_API_KEY

def ask_assistant(question):
    """
    Directly asks the OpenAI assistant a question using gpt-4o-mini.
    """
    if not OPENAI_API_KEY:
        return "Assistant error: OPENAI_API_KEY is not configured."
    
    client = OpenAI(api_key=OPENAI_API_KEY)

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity assistant for AivulnHunter."},
                {"role": "user", "content": question}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Assistant error: {str(e)}"
