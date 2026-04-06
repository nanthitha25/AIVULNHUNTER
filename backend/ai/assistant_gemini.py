import google.generativeai as genai
from ..config import GEMINI_API_KEY

# Configure the API key
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("Warning: GEMINI_API_KEY not found in environment.")

# Use gemini-1.5-flash (stable) to avoid 503 capacity errors
model = genai.GenerativeModel("gemini-1.5-flash")

def ask_assistant(question):
    """
    Directly asks the Gemini assistant a question.
    """
    try:
        if not GEMINI_API_KEY:
            return "Assistant error: GEMINI_API_KEY is not configured."
        
        response = model.generate_content(question)
        return response.text
    except Exception as e:
        return f"Assistant error: {str(e)}"
