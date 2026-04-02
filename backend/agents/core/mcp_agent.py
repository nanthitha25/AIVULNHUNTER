import logging
import json
from typing import Dict, Any, List
from backend.agents.base import BaseAgent
from backend.agents.mcp_tools import MCP_TOOLS_SCHEMA

logger = logging.getLogger(__name__)

MAX_MCP_TOOL_CALLS = 3

class MCPAgent(BaseAgent):
    """
    Experimental MCP reasoning layer. Outputs structured JSON tool calls.
    """
    
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        profile = state.get("profile", {})
        
        logger.info(f"[MCP_AGENT] analyzing target: {target} with tools: {[t['name'] for t in MCP_TOOLS_SCHEMA]}")
        
        # Simulating LLM response (in reality, parsed from LLM string output)
        tool_calls = []
        
        target_str = str(target).lower() if target else ""
        if "api" in target_str or profile.get("type") == "REST_API":
            # Model decides to run an API scan
            tool_calls.append({
                "name": "api_vulnerability_scan",
                "arguments": {
                    "endpoint": f"{target}/users/admin",
                    "method": "GET"
                }
            })
        
        tool_calls.append({
            "name": "payload_generator",
            "arguments": {
                "vuln_type": "PromptInjection" if profile.get("type") == "LLM_API" else "SQLi"
            }
        })
        
        # Internal Guard: Limit tool calls
        if len(tool_calls) > MAX_MCP_TOOL_CALLS:
            logger.warning(f"[MCP_AGENT] Truncating tool calls from {len(tool_calls)} to {MAX_MCP_TOOL_CALLS}")
            tool_calls = tool_calls[:MAX_MCP_TOOL_CALLS]

        validated_tool_calls = []
        for call in tool_calls:
            if self._validate_tool_call(call):
                validated_tool_calls.append(call)
            else:
                logger.error(f"[MCP_SCHEMA_ERROR] Discarding invalid tool call: {call}")
        
        return {
            "tool_calls": validated_tool_calls,
            "reasoning": "Determined target has API surface, executing structured tool calls."
        }
        
    def _validate_tool_call(self, tool_call: Dict[str, Any]) -> bool:
        """
        Strictly validates the tool call against the schema.
        No fuzzy matching, no repair logic.
        """
        if not isinstance(tool_call, dict):
            return False
            
        name = tool_call.get("name")
        arguments = tool_call.get("arguments")
        
        if not name or not isinstance(name, str) or not isinstance(arguments, dict):
            return False
            
        # Find matching schema
        schema = next((s for s in MCP_TOOLS_SCHEMA if s["name"] == name), None)
        if not schema:
            return False
            
        # Validate required fields
        required = schema.get("input_schema", {}).get("required", [])
        for req_field in required:
            if req_field not in arguments:
                return False
                
            # Basic strict string checking (could use pydantic/jsonschema)
            if not isinstance(arguments[req_field], str):
                return False
                
        # Reject extra fields
        allowed_props = schema.get("input_schema", {}).get("properties", {}).keys()
        for key in arguments.keys():
            if key not in allowed_props:
                return False

        return True
        

