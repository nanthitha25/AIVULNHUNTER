from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from ..ai.assistant_gemini import ask_assistant
from ..ai.retry_wrapper import retry_call

router = APIRouter()

class AssistantQuery(BaseModel):
    question: str
    scan_summary: Optional[str] = None

@router.post("/assistant")
async def ai_assistant(query: AssistantQuery):
    """
    API endpoint for the AI assistant. Uses retry logic to handle capacity issues.
    Incorporates scan_summary context if provided for RAG-style responses.
    """
    # Build prompt context if scan_summary is available
    if query.scan_summary:
        full_prompt = f"""
Scan result:
{query.scan_summary}

User question:
{query.question}

Please provide a detailed explanation based on the scan results above.
"""
    else:
        full_prompt = query.question

    # Use retry_call to wrap the assistant call
    response = retry_call(ask_assistant, full_prompt)

    if response == "AI service temporarily unavailable. Please try again later.":
         raise HTTPException(status_code=503, detail=response)

    return {"answer": response}
