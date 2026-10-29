import google.generativeai as genai
import os
from dotenv import load_dotenv

# Ensure .env is loaded
load_dotenv()

def ask_gemini(system_prompt, user_prompt):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY missing")
        raise RuntimeError("GEMINI_API_KEY not configured")

    genai.configure(api_key=api_key)
    
    print("Calling Gemini Flash Latest...")
    model = genai.GenerativeModel("gemini-flash-latest", system_instruction=system_prompt)
    
    response = model.generate_content(user_prompt)
    return response.text
