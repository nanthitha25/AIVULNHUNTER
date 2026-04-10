import google.generativeai as genai
import os
from dotenv import load_dotenv

# Ensure .env is loaded
load_dotenv()

def ask_gemini(prompt):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY missing")
        raise RuntimeError("GEMINI_API_KEY not configured")

    genai.configure(api_key=api_key)
    
    print("Calling Gemini 1.5 Flash...")
    model = genai.GenerativeModel("gemini-1.5-flash")
    
    response = model.generate_content(prompt)
    return response.text
