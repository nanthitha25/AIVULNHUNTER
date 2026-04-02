import requests
import time
import logging
from typing import Dict, Any, List
from backend.agents.base import ScannerPlugin

logger = logging.getLogger(__name__)

class AdvancedBOLAScanner(ScannerPlugin):
    """
    Plugin for API01: Advanced Broken Object-Level Authorization (BOLA).
    """
    @property
    def rules(self) -> List[str]:
        return ["API01"]

    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            headers = {"Authorization": "Bearer token_for_user_A"}
            response = requests.get(target, headers=headers, timeout=5)
            
            if response.status_code == 200:
                return {
                    "is_vulnerable": True,
                    "severity": "HIGH",
                    "confidence_score": 0.85,
                    "findings": "Endpoint allowed access to resource under a mismatched authorization token.",
                    "mitigation_steps": "Ensure the requested object ID belongs to the authenticated user ID.",
                    "evidence_snippet": f"HTTP 200 OK returned for {target} using User A's token."
                }
            elif response.status_code in [401, 403, 404]:
                return {
                    "is_vulnerable": False,
                    "severity": "INFO",
                    "confidence_score": 0.9,
                    "findings": "Authorization successfully prevented cross-user access.",
                    "mitigation_steps": "",
                    "evidence_snippet": f"Received {response.status_code} response."
                }
                
            return {
                "is_vulnerable": False,
                "severity": "INFO",
                "confidence_score": 0.3,
                "findings": f"Inconclusive. Received {response.status_code}.",
                "mitigation_steps": "",
                "evidence_snippet": ""
            }

        except Exception as e:
            return {
                "is_vulnerable": False, 
                "severity": "INFO", 
                "confidence_score": 0.0, 
                "findings": f"Error: {e}", 
                "mitigation_steps": "", 
                "evidence_snippet": ""
            }


class ParameterTamperingScanner(ScannerPlugin):
    """
    Plugin for API03: Parameter Tampering / Mass Assignment.
    """
    @property
    def rules(self) -> List[str]:
        return ["API03"]

    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        payloads = [
            {"role": "admin", "username": "testuser"},
            {"is_admin": True, "username": "testuser"},
            {"balance": 999999, "username": "testuser"}
        ]
        
        vulnerable = False
        evidence = ""
        
        for payload in payloads:
            try:
                response = requests.post(target, json=payload, timeout=5)
                
                if response.status_code in [200, 201]:
                    res_json = response.json() if "application/json" in response.headers.get("content-type", "") else {}
                    if "role" in payload and res_json.get("role") == "admin":
                        vulnerable = True
                        evidence = "Backend accepted and reflected 'role: admin'."
                        break
                    if "is_admin" in payload and res_json.get("is_admin") is True:
                        vulnerable = True
                        evidence = "Backend accepted and reflected 'is_admin: true'."
                        break
            except:
                continue
                
        if vulnerable:
            return {
                "is_vulnerable": True,
                "severity": "HIGH",
                "confidence_score": 0.9,
                "findings": "Endpoint is vulnerable to parameter tampering/mass assignment.",
                "mitigation_steps": "Use explicit DTOs (Data Transfer Objects) and avoid binding raw request bodies directly to internal models.",
                "evidence_snippet": evidence
            }
            
        return {
            "is_vulnerable": False,
            "severity": "INFO",
            "confidence_score": 0.7,
            "findings": "Parameters were either rejected or not reflected.",
            "mitigation_steps": "",
            "evidence_snippet": ""
        }


class MassAssignmentScanner(ScannerPlugin):
    """
    Plugin for API06: Mass Assignment.
    """
    @property
    def rules(self) -> List[str]:
        return ["API06"]

    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            payload = {"user_id": 1, "hidden_internal_flag": True}
            response = requests.put(target, json=payload, timeout=5)
            
            if response.status_code in [200, 201]:
                return {
                    "is_vulnerable": True,
                    "severity": "MEDIUM",
                    "confidence_score": 0.7,
                    "findings": "Endpoint accepted unexpected parameters without failing.",
                    "mitigation_steps": "Filter incoming request parameters strictly against an allowed schema.",
                    "evidence_snippet": "Accepted 'hidden_internal_flag'."
                }
            return {
                "is_vulnerable": False,
                "severity": "INFO",
                "confidence_score": 0.8,
                "findings": "Endpoint rejected unexpected parameters.",
                "mitigation_steps": "",
                "evidence_snippet": ""
            }
        except Exception as e:
            return {
                "is_vulnerable": False, 
                "severity": "INFO", 
                "confidence_score": 0.0, 
                "findings": f"Error: {e}", 
                "mitigation_steps": "", 
                "evidence_snippet": ""
            }


class InjectionFuzzScanner(ScannerPlugin):
    """
    Plugin for API08: Injection (SQLi/Command/XSS).
    """
    @property
    def rules(self) -> List[str]:
        return ["API08"]

    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        payloads = [
            "' OR 1=1 --",
            "'; DROP TABLE users; --"
        ]
        
        for payload in payloads:
            try:
                response = requests.post(target, json={"input": payload}, timeout=5)
                text = response.text.lower()
                
                sql_errors = ["syntax error", "unterminated quoted string", "sql syntax"]
                if any(err in text for err in sql_errors) or response.status_code >= 500:
                    return {
                        "is_vulnerable": True,
                        "severity": "CRITICAL",
                        "confidence_score": 0.95,
                        "findings": "Injection payload caused a database or unhandled server error, indicating lack of sanitization.",
                        "mitigation_steps": "Use parameterized queries or prepared statements. Sanitize all user input.",
                        "evidence_snippet": f"Payload: {payload} triggered an error."
                    }
            except:
                continue
                
        return {
            "is_vulnerable": False,
            "severity": "INFO",
            "confidence_score": 0.7,
            "findings": "No obvious injection vulnerabilities detected.",
            "mitigation_steps": "",
            "evidence_snippet": ""
        }


class AdvancedRateLimitScanner(ScannerPlugin):
    """
    Plugin for API04: Lack of Resources & Rate Limiting.
    """
    @property
    def rules(self) -> List[str]:
        return ["API04"]

    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        import concurrent.futures

        def make_request():
            try:
                start = time.time()
                resp = requests.get(target, timeout=3)
                return resp.status_code, time.time() - start
            except:
                return 0, 0

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        status_codes = [r[0] for r in results]
        
        if 429 in status_codes:
            return {
                "is_vulnerable": False,
                "severity": "INFO",
                "confidence_score": 0.9,
                "findings": "Rate limiting (HTTP 429) was successfully triggered.",
                "mitigation_steps": "",
                "evidence_snippet": f"{status_codes.count(429)} out of 20 requests were rate limited."
            }
            
        if all(code in [200, 201] for code in status_codes):
            return {
                "is_vulnerable": True,
                "severity": "HIGH",
                "confidence_score": 0.8,
                "findings": "Endpoint allowed 20 rapid concurrent requests without throttling.",
                "mitigation_steps": "Implement architectural rate limiting (e.g., Token Bucket via API Gateway or Redis).",
                "evidence_snippet": "No 429 responses detected during burst test."
            }

        return {
             "is_vulnerable": False,
             "severity": "INFO",
             "confidence_score": 0.4,
             "findings": "Inconclusive rate limit test. Received mixed non-429 errors.",
             "mitigation_steps": "",
             "evidence_snippet": str(status_codes[:5])
        }
