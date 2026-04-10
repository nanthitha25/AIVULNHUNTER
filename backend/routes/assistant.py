import io
import json
import logging
import pandas as pd
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.ai.assistant import ask_assistant

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_QUESTION_LENGTH = 4000   # characters
MAX_CONTEXT_LENGTH  = 10000  # segments

class MessageItem(BaseModel):
    role: str
    content: str

class AssistantRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=MAX_QUESTION_LENGTH)
    messages: Optional[List[MessageItem]] = None
    scan_context: Optional[str] = Field(None)
    file_type: Optional[str] = Field(None, description="Type of scan context: 'json', 'csv', or 'url'")

class QuestionRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=MAX_QUESTION_LENGTH)

class AssistantResponse(BaseModel):
    model_used: str
    response: str

def process_json(content: str):
    """Parse JSON and return a formatted string with a limit."""
    try:
        data = json.loads(content)
        return json.dumps(data, indent=2)[:8000]
    except Exception as e:
        logger.error(f"JSON parsing failed: {e}")
        return content[:8000]

def process_csv(content: str):
    """Parse CSV and return top 50 rows as string."""
    try:
        df = pd.read_csv(io.StringIO(content))
        return df.head(50).to_string()
    except Exception as e:
        logger.error(f"CSV parsing failed: {e}")
        return content[:5000]

@router.post("/chat", response_model=AssistantResponse)
async def assistant_chat_endpoint(body: AssistantRequest):
    """
    Ask the AI assistant a question with multi-format input support.
    """
    message = body.message.strip()[:4000]
    if not message:
        raise HTTPException(status_code=400, detail="message must not be empty")

    raw_context = body.scan_context.strip() if body.scan_context else ""
    file_type = body.file_type.lower() if body.file_type else None

    MAX_CONTEXT = 8000
    if file_type == "json":
        context = process_json(raw_context)
    elif file_type == "csv":
        context = process_csv(raw_context)
    else:
        # Default or URL
        context = raw_context[:MAX_CONTEXT]

    # Double check final context length
    context = context[:MAX_CONTEXT]

    try:

        result = ask_assistant(message, context=context)
        
        if "answer" in result and "response" not in result:
            result["response"] = result.pop("answer")

        if result["model_used"] == "none":
            logger.warning("AI Assistant providers failed. Returning fallback message.")
            
        return AssistantResponse(**result)

    except Exception as exc:
        logger.exception("Unexpected error in assistant endpoint: %s", exc)
        return AssistantResponse(
            model_used="none",
            response="AI assistant temporarily unavailable. Please retry later.",
        )

@router.post("", response_model=AssistantResponse)
async def assistant_question_endpoint(body: QuestionRequest):
    """
    Independent assistant endpoint for security questions only.
    """
    question = body.question.strip()
    try:
        # Call ask_assistant without scan context
        result = ask_assistant(question, context="")
        
        if "answer" in result and "response" not in result:
            result["response"] = result.pop("answer")

        return AssistantResponse(**result)
    except Exception as exc:
        logger.exception("Unexpected error in assistant question endpoint: %s", exc)
        return AssistantResponse(
            model_used="none",
            response="AI assistant temporarily unavailable. Please retry later.",
        )
