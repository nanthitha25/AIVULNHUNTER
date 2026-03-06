from fastapi import APIRouter, HTTPException
from typing import Optional
from pydantic import BaseModel
from backend.services.assistant_service import get_assistant_response

router = APIRouter(prefix="/assistant", tags=["Assistant"])


class ChatRequest(BaseModel):
    message: str
    scan_id: Optional[str] = None
    context: Optional[str] = None

class ChatResponse(BaseModel):
    response: str


@router.post("/chat", response_model=ChatResponse)
async def chat_with_assistant(request: ChatRequest):
    """
    AI Security Assistant Chat Endpoint.
    Accepts a user message and optional scan_id/context for RAG-enriched responses.
    No authentication required — the assistant is publicly accessible.
    """
    if not request.message or not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    try:
        reply = await get_assistant_response(
            message=request.message,
            scan_id=request.scan_id,
            context=request.context
        )
        return ChatResponse(response=reply)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan-explain/{scan_id}", response_model=ChatResponse)
async def explain_scan_results(scan_id: str):
    """
    Auto-generate a professional explanation of an existing scan's vulnerabilities.
    No authentication required.
    """
    try:
        prompt = (
            "Please provide a clear, professional summary of this security scan. "
            "Explain what the major vulnerabilities mean, why they are dangerous, "
            "and summarize the recommended mitigations in bullet points."
        )
        reply = await get_assistant_response(message=prompt, scan_id=scan_id)
        return ChatResponse(response=reply)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

