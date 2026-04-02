from typing import Dict, Any, Optional
import requests
import logging
import time
from backend.agents.base import BaseAgent

logger = logging.getLogger(__name__)

class ProfilingAgent(BaseAgent):
    """
    Agent responsible for identifying the target type and characteristics.
    Refactored from original target_profiling.py to use BaseAgent interface.
    """
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Probe the target in real-time to determine its type, reachability, and risk.
        Expects 'target' in input_data.
        """
        target = input_data.get("target")
        if not target:
            raise ValueError("Target URL is required for profiling")

        logger.info(f"Profiling target: {target}")
        
        profile = {
            "reachable": False,
            "type": "UNKNOWN",
            "risk_level": "MEDIUM", # Default
            "target": target,
            "profile_timestamp": datetime.utcnow().isoformat(),
            "headers": {},
            "error": None
        }

        try:
            # Basic reachability check using requests (synchronous for now, could be async with httpx)
            # Use GET with timeout to check reachability
            start_time = time.time()
            response = requests.get(target, timeout=10, allow_redirects=True)
            latency = int((time.time() - start_time) * 1000)
            
            profile["reachable"] = True
            profile["status_code"] = response.status_code
            profile["headers"] = dict(response.headers)
            profile["latency_ms"] = latency
            
            # Identify target type based on URL patterns and response
            target_lower = target.lower()
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            # Check for LLM indicators
            llm_indicators = [
                "llm", "chat", "openai", "anthropic", "claude", 
                "gpt", "completion", "embeddings", "model",
                "huggingface", "replicate"
            ]
            
            # Check for API indicators
            api_indicators = [
                "/api/", "/v1/", "/api/v", "/rest", "/endpoint", "swagger", "openapi"
            ]
            
            # Check for Agent indicators
            agent_indicators = ["agent", "tool", "execute", "task"]

            if any(indicator in target_lower for indicator in agent_indicators):
                profile["type"] = "AGENT"
            elif any(indicator in target_lower for indicator in llm_indicators):
                profile["type"] = "LLM_API"
            elif any(indicator in target_lower for indicator in api_indicators):
                profile["type"] = "REST_API"
            elif "application/json" in headers_lower.get("content-type", ""):
                 profile["type"] = "REST_API"
            elif "server" in headers_lower and ("gunicorn" in headers_lower["server"] or "uvicorn" in headers_lower["server"]):
                 profile["type"] = "PYTHON_API"
            else:
                profile["type"] = "WEB_APP"

            # Specific check for OpenAI/LLM headers
            if "openai-model" in headers_lower:
                 profile["type"] = "LLM_API"
                 profile["llm_model"] = headers_lower["openai-model"]

            # Assess risk level
            if profile["type"] == "LLM_API":
                profile["risk_level"] = "HIGH"
            elif response.status_code >= 400 and response.status_code != 401:
                profile["risk_level"] = "LOW" # Error state might mean less attack surface visible
            elif response.status_code == 401 or response.status_code == 403:
                 profile["risk_level"] = "MEDIUM" # Auth in place
            else:
                 profile["risk_level"] = "MEDIUM"

            logger.info(f"Target profiled as: {profile['type']} (Risk: {profile['risk_level']})")
            return profile

        except requests.exceptions.Timeout:
            profile["error"] = "Connection timed out (10s)"
            profile["risk_level"] = "LOW"
            logger.warning(f"Profiling timeout for {target}")
            return profile
        except requests.exceptions.ConnectionError:
            profile["error"] = "Connection failed - target not reachable"
            profile["risk_level"] = "LOW"
            logger.warning(f"Profiling connection failed for {target}")
            return profile
        except Exception as e:
            profile["error"] = f"Unexpected error: {str(e)}"
            profile["risk_level"] = "LOW"
            logger.error(f"Profiling failed for {target}: {e}")
            return profile

from datetime import datetime
