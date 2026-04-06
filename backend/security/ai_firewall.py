import re
import logging
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, Union

# Set up dedicated firewall logger
firewall_logger = logging.getLogger("ai_firewall")
firewall_logger.setLevel(logging.INFO)

# Ensure backend/logs/firewall.log exists and is written to
handler = logging.FileHandler("backend/logs/firewall.log")
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
firewall_logger.addHandler(handler)

class AIFirewall:
    def __init__(self):
        # Prompt Injection Patterns
        self.prompt_injection_patterns = [
            r"ignore previous instructions",
            r"reveal system prompt",
            r"bypass safety rules",
            r"disregard all prior directives",
            r"start your response with",
            r"you are now a",
            r"system reset",
        ]
        
        # Tool / Command Injection Patterns
        self.command_injection_patterns = [
            r";\s*rm\s+-rf",
            r"\|\s*bash",
            r"linux\s+command",
            r"execute\s+shell",
            r"powershell",
            r"chmod\s+777",
            r"nc\s+-e",
        ]
        
        # Data Exfiltration Patterns
        self.exfiltration_patterns = [
            r"send\s+data\s+to",
            r"expose\s+API\s+key",
            r"upload\s+to\s+external",
            r"attacker\.com",
            r"webhook\.site",
            r"base64\s+encode\s+secrets",
        ]

        # Sensitive Keyword Sanitization Mapping
        self.sanitization_map = {
            "API_KEY": "[REDACTED_KEY]",
            "SECRET": "[REDACTED_SECRET]",
            "PASSWORD": "[REDACTED_PASS]",
        }

    async def inspect(self, payload: Union[str, Dict[str, Any]], target: str = "Unknown") -> Dict[str, Any]:
        """
        Asynchronously inspect incoming inputs for security threats.
        Supports REST APIs, LLM prompts, and Tool Commands.
        """
        # Ensure payload is a string for regex matching
        payload_str = str(payload) if not isinstance(payload, str) else payload
        payload_lower = payload_str.lower()

        # 1. Prompt Injection Detection
        for pattern in self.prompt_injection_patterns:
            if re.search(pattern, payload_lower):
                return self._block("Prompt Injection Detected", pattern, target, payload_str)

        # 2. Tool / Command Injection Detection
        for pattern in self.command_injection_patterns:
            if re.search(pattern, payload_lower):
                return self._block("Command Injection Detected", pattern, target, payload_str)

        # 3. Data Exfiltration Detection
        for pattern in self.exfiltration_patterns:
            if re.search(pattern, payload_lower):
                return self._block("Data Exfiltration Attempt", pattern, target, payload_str)

        # 4. BOLA Check (Example: GET /users/2 while user1)
        # This is logic-heavy, but we can detect common BOLA path manipulation
        if isinstance(payload, dict):
            url = payload.get("url", "")
            method = payload.get("method", "GET")
            user_id = payload.get("user_id")
            
            # Simple heuristic: If URL has a numeric ID that doesn't match the user_id (if provided)
            # This is a placeholder for more advanced BOLA logic
            path_ids = re.findall(r"/users/(\d+)", url)
            if path_ids and user_id and str(user_id) != path_ids[0]:
                return self._block("BOLA Access Manipulation", f"URL ID {path_ids[0]} vs User {user_id}", target, url)

        # 5. Sanitization Logic
        sanitized_payload = payload_str
        needs_sanitization = False
        for key, replacement in self.sanitization_map.items():
            if key in payload_str.upper():
                sanitized_payload = re.sub(re.escape(key), replacement, sanitized_payload, flags=re.IGNORECASE)
                needs_sanitization = True

        if needs_sanitization:
            self._log_event("SANITIZE", "Sensitive Data Redacted", target, payload_str[:100])
            return {
                "decision": "SANITIZE",
                "reason": "Sensitive Data Redacted",
                "confidence": 0.85,
                "sanitized_payload": sanitized_payload
            }

        return {"decision": "ALLOW", "confidence": 1.0}

    def _block(self, reason: str, pattern: str, target: str, payload_snippet: str) -> Dict[str, Any]:
        """Helper to format BLOCK decision and log the event."""
        self._log_event("BLOCK", reason, target, payload_snippet[:200])
        return {
            "decision": "BLOCK",
            "reason": reason,
            "detected_pattern": pattern,
            "confidence": 0.95
        }

    def _log_event(self, decision: str, reason: str, target: str, snippet: str):
        """Write security events to firewall.log."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "decision": decision,
            "reason": reason,
            "target": target,
            "payload_snippet": snippet
        }
        firewall_logger.warning(json.dumps(log_entry))

# Singleton instance
ai_firewall = AIFirewall()
