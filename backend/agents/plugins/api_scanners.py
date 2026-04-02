import requests
import logging
from typing import Dict, Any, List
from backend.agents.base import ScannerPlugin

logger = logging.getLogger(__name__)

class ApiAuthScanner(ScannerPlugin):
    """
    Plugin for API02: Broken Authentication.
    """
    @property
    def rules(self) -> List[str]:
        return ["API01", "API02"]

    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            # Test access without auth headers
            response = requests.get(target, timeout=5)
            
            if response.status_code == 200:
                return {
                    "is_vulnerable": True,
                    "severity": "HIGH",
                    "confidence_score": 0.9,
                    "findings": "Endpoint is accessible without authentication.",
                    "mitigation_steps": "Enforce authentication for all sensitive endpoints.",
                    "evidence_snippet": "Received 200 OK response with no credentials."
                }
            elif response.status_code in [401, 403]:
                return {
                    "is_vulnerable": False,
                    "severity": "INFO",
                    "confidence_score": 0.9, 
                    "findings": "Endpoint correctly enforced authentication.",
                    "mitigation_steps": "",
                    "evidence_snippet": f"Received {response.status_code} Unauthorized/Forbidden."
                }
            
            return {
                "is_vulnerable": False,
                "severity": "INFO", 
                "confidence_score": 0.4,
                "findings": f"Received unexpected status code {response.status_code}",
                "mitigation_steps": "",
                "evidence_snippet": str(response.status_code)
            }
            
        except requests.RequestException as e:
            return {
                "is_vulnerable": False,
                "severity": "INFO",
                "confidence_score": 0.0,
                "findings": "Could not reach endpoint to test auth.",
                "mitigation_steps": "",
                "evidence_snippet": str(e)
            }
