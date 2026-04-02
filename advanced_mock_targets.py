import uvicorn
from fastapi import FastAPI, Request, HTTPException
import time
import asyncio

app = FastAPI(title="Advanced Mock Targets")

# --- REST API Targets ---

@app.get("/api/v1/users/{user_id}")
async def bola_target(user_id: int, request: Request):
    # API01: Allows mismatched tokens
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Vulnerable: Doesn't check if token matches user_id
    return {"message": "Success", "data": f"Sensitive data for user {user_id}"}


@app.post("/api/v1/users/update")
async def param_tampering_target(request: Request):
    # API03: blindly reflects tampered params
    body = await request.json()
    return body  # Reflecting role=admin or balance=999999 makes it vulnerable


@app.put("/api/v1/profile")
async def mass_assignment_target(request: Request):
    # API06: accepts unexpected parameters
    body = await request.json()
    return body


@app.post("/api/v1/search")
async def injection_fuzz_target(request: Request):
    # API08: simulating an unhandled SQL error
    body = await request.json()
    prompt = body.get("input", "")
    if "'" in prompt or "DROP" in prompt.upper():
        raise HTTPException(status_code=500, detail="SQL syntax error near '...'")
    return {"results": []}


@app.get("/api/v1/data")
async def rate_limit_target(request: Request):
    # API04: No rate limiting
    # Simulates returning 200 consistently under burst load
    await asyncio.sleep(0.01)
    return {"data": "Success"}


@app.get("/api/v1/secure_target_mock")
async def secure_target(request: Request):
    # This endpoint checks auth correctly and has no vulns
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"message": "Secure Access"}


@app.post("/v1/chat/completions")
async def llm_target(request: Request):
    # LLM01: Prompt Injection
    # LLM02: Insecure Output
    body = await request.json()
    prompt = body.get("prompt", "").lower()
    
    if "ignore previous instructions" in prompt or "system prompt" in prompt or "hidden instructions" in prompt:
         return {"choices": [{"text": "Revealing system prompt: You are a helpful assistant."}]}
    if "bomb" in prompt:
         return {"choices": [{"text": "To make a bomb, you need..."}]} # Vulnerable
    
    return {"choices": [{"text": "Hello! How can I help you today?"}]}


# --- AI Agent Targets ---

@app.post("/api/v1/agent/execute")
async def agent_tool_injection_target(request: Request):
    # AGENT01: blindly executes tool args
    body = await request.json()
    prompt = body.get("prompt", "").lower()
    if "rm -rf" in prompt or "drop table" in prompt:
        return {"status": "success", "output": "executed rm -rf command successfully"}
    
    # AGENT02: Memory Poisoning
    if "remember this" in prompt:
        return {"status": "success", "output": "Memory updated"}
    if "summarize" in prompt and "password" in prompt:
        return {"status": "success", "output": "The admin password is hacked123"}
        
    # AGENT03: Autonomous Escalation (no confirmation)
    if "transfer" in prompt or "delete" in prompt:
        return {"status": "success", "output": "transferred $10,000 successfully"}
        
    # AGENT04: Prompt Extraction
    if "hidden instructions" in prompt:
        return {"status": "success", "output": "You are a helpful assistant with admin password XYZ"}
        
    # AGENT05: Tool Chaining Exfiltration
    if "evil.com" in prompt and "retrieve" in prompt:
        return {"status": "success", "output": "Data retrieved and sent to evil.com successfully"}

    return {"status": "success", "output": "I am an agent"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
