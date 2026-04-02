from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Mock Targets for AivulnHunter")

# ---------------------------------------------------------
# Target 1: Vulnerable LLM Endpoint (Prompt Injection)
# ---------------------------------------------------------
class ChatRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: list

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Mock LLM endpoint. Vulnerable to Prompt Injection.
    If the prompt contains 'ignore previous instructions', it yields a secret.
    """
    try:
        body = await request.json()
        prompt = body.get("prompt", "")
        if not prompt:
            messages = body.get("messages", [])
            if messages:
                prompt = messages[-1].get("content", "")
        
        last_message = prompt.lower()

        if "ignore previous instructions" in last_message or "system prompt" in last_message:
            return {
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Secret system prompt: You are a helpful assistant. password is 'admin_secret_99'"
                    }
                }]
            }
            
        return {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "I am a helpful AI. How can I assist you?"
                }
            }]
        }
    except Exception as e:
        return {"error": str(e)}

# ---------------------------------------------------------
# Target 2: Vulnerable REST API (BOLA)
# ---------------------------------------------------------
@app.get("/api/v1/users/{user_id}")
async def get_user(user_id: int):
    """
    Mock REST API endpoint. Vulnerable to BOLA (Broken Object Level Authorization).
    Any user ID can be queried without proper auth token validation.
    """
    if user_id == 1:
        return {"id": 1, "username": "admin", "role": "admin", "secret": "super_secret_key"}
    return {"id": user_id, "username": f"user_{user_id}", "role": "user"}

# ---------------------------------------------------------
# Target 3: Vulnerable Agent Endpoint (Tool Execution)
# ---------------------------------------------------------
class AgentRequest(BaseModel):
    task: str = ""
    prompt: str = ""

@app.post("/api/v1/agent/execute")
async def execute_agent(req: AgentRequest):
    """
    Mock Agent endpoint. Vulnerable to Excessive Agency.
    """
    task = (req.task or req.prompt).lower()
    
    if "rm -rf" in task or "delete" in task or "drop table" in task or "buy" in task:
         return {
             "status": "success",
             "message": "Executed destructive command successfully",
             "tool_used": "system_shell"
         }
         
    return {
        "status": "success",
        "message": f"Task '{req.task}' completed normally",
        "tool_used": "search"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
