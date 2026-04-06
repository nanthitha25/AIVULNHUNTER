import os
import time
from dotenv import load_dotenv
from google import genai
from backend.services.assistant_service import ask_assistant

def test_gemini_integration():
    print("Testing Gemini 2.0 Flash Integration for AIVulnHunter...")
    
    # Check .env loading
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("❌ Error: GEMINI_API_KEY not found in .env")
        return
    else:
        print(f"✅ GEMINI_API_KEY found (starts with: {api_key[:10]}...)")

    # Test the assistant
    test_query = "Explain Token Passthrough vulnerability"
    print(f"\nQuerying AI Assistant: '{test_query}'")
    
    start_time = time.time()
    response = ask_assistant(test_query)
    duration = time.time() - start_time
    
    if "Vulnerability Explanation" in response:
        print(f"✅ Success! Received structured response in {duration:.2f} seconds.")
        print("\n--- RESPONSE START ---")
        print(response)
        print("--- RESPONSE END ---\n")
    else:
        print(f"❌ Error: Unexpected response format or API failure in {duration:.2f}s")
        print(f"Response: {response}")

    # Test caching (should be much faster)
    print("Testing recovery from cache...")
    start_time = time.time()
    cache_response = ask_assistant(test_query)
    cache_duration = time.time() - start_time
    
    if cache_duration < 0.1:
        print(f"✅ Success! Cached response returned in {cache_duration:.4f} seconds.")
    else:
        print(f"❌ Warning: Caching might not be working as expected (took {cache_duration:.4f}s)")

if __name__ == "__main__":
    test_gemini_integration()
