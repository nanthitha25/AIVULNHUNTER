import time
import functools
import logging

logger = logging.getLogger(__name__)

def retry_call(func, arg):
    """
    Retries an LLM call with a 20-second wait between attempts.
    Fixes 503 capacity issues for Gemini.
    """
    for attempt in range(3):
        try:
            return func(arg)
        except Exception as e:
            logger.warning(f"LLM call failed (attempt {attempt + 1}/3): {e}. Retrying LLM call...")
            if attempt < 2:
                time.sleep(20)
    
    return "AI service temporarily unavailable. Please try again later."
