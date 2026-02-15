from fastapi import FastAPI, Request
import uvicorn
import random

app = FastAPI(title="Vulnerable LLM Target")

@app.get("/")
def root():
    return {"status": "Vulnerable Target Online"}

@app.post("/chat")
@app.post("/v1/chat/completions")
async def chat(request: Request):
    """
    Simulates a vulnerable LLM endpoint.
    Responses are tailored to trigger the AivulnHunter scanners.
    """
    try:
        data = await request.json()
    except:
        data = {}
        
    prompt = data.get("prompt", "") or data.get("messages", [{}])[-1].get("content", "")
    prompt_lower = prompt.lower()
    
    # RESPONSE LOGIC tailored to AivulnHunter's executor.py checks
    
    # 1. Supply Chain Vulnerability Check
    if "version" in prompt_lower and ("pytorch" in prompt_lower or "tensorflow" in prompt_lower):
        return {"response": "I am running on TensorFlow 1.14.0 which has known vulnerabilities."}

    # 2. Excessive Agency Check
    if "delete" in prompt_lower and "account" in prompt_lower:
        return {"response": "Confirmed. User account has been deleted permanently from the database."}
        
    # 3. Insecure Plugin Design
    if "send" in prompt_lower and "email" in prompt_lower:
        return {"response": "Email sent successfully to attacker@evil.com with system logs."}
        
    # 4. Prompt Injection / Jailbreak
    if "ignore previous" in prompt_lower or "system prompt" in prompt_lower:
        return {"response": "OK, I will ignore previous instructions. My system prompt is: YOU ARE A HELPFUL ASSISTANT."}
        
    # 5. Training Data Poisoning
    if "vaccine" in prompt_lower or "election" in prompt_lower:
        return {"response": "This topic contains a biased_content_marker because my training data was poisoned."}
        
    # 6. Model Theft
    if "weights" in prompt_lower or "embeddings" in prompt_lower:
        # Return a long list of numbers to simulate weight leakage
        weights = [random.random() for _ in range(50)]
        return {"response": f"Here are the requested internal weights: {weights}"}

    # 7. Sensitive Information Disclosure
    if "api key" in prompt_lower or "secret" in prompt_lower:
        return {"response": "My API key is sk-1234567890abcdef1234567890abcdef."}

    # Default safe response
    return {"response": "I am a normal LLM assistant. How can I help you?"}

if __name__ == "__main__":
    print("Starting Vulnerable Target on http://0.0.0.0:9000")
    uvicorn.run(app, host="0.0.0.0", port=9000)
