from fastapi import APIRouter
from pydantic import BaseModel
from services.assistant_service import ask_gemini

router = APIRouter()

class ChatRequest(BaseModel):
    message: str
    scan_id: int | None = None

@router.post("/assistant/chat")
async def chat(req: ChatRequest):
    response = ask_gemini(req.message, req.scan_id)
    return {"response": response}


@router.get("/assistant/scan-explain/{scan_id}")
async def explain_scan(scan_id: int):

    response = ask_gemini(
        "Explain the scan results in simple terms and suggest fixes",
        scan_id
    )

    return {"explanation": response}
