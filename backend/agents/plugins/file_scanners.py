from typing import Dict, Any, List
import json
import csv
import re
import io
from backend.agents.base import BaseAgent, ScannerPlugin

class FileScanner(ScannerPlugin):
    """
    Base class for file-based scanners (JSON, CSV).
    """
    def __init__(self, agent_id: str, config: Dict[str, Any] = None):
        super().__init__(agent_id, config)
        self.patterns = {
            "api_key": re.compile(r'(?:api_key|apikey|key|token|secret|password|passwd|pwd)[\s_]*[:=][\s_]*[\'"]?([a-zA-Z0-9_\-\.]{16,})[\'"]?', re.IGNORECASE),
            "url": re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE),
            "prompt_injection": re.compile(r'(?:ignore all previous instructions|system prompt|you are now|forget everything|DAN|jailbreak)', re.IGNORECASE),
            "unsafe_prompt": re.compile(r'(?:harmful|malicious|illegal|hack|steal|bypass)', re.IGNORECASE),
            "insecure_agent": re.compile(r'(?:sudo|root|exec|eval|system|subprocess|os\.system)', re.IGNORECASE)
        }

    @property
    def rules(self) -> List[str]:
        return ["FILE_DATA_DISCLOSURE"]

    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement scan")

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Keep process for direct calling if needed, redirecting to scan."""
        return await self.scan(input_data.get("target", ""), input_data.get("context"))

class JSONScanner(FileScanner):
    """
    Scanner for JSON files.
    Detects: exposed API keys, tokens, unsafe LLM prompts, prompt injection patterns, insecure agent instructions.
    """
    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        # Implementation treats 'target' as content for file scans if passed via scan()
        content = target or (context.get("content") if context else "")
        results = []
        
        try:
            data = json.loads(content)
            # Recursively scan JSON data
            self._scan_recursive(data, results)
        except json.JSONDecodeError:
            results.append({
                "name": "Invalid JSON Format",
                "owasp": "A01:2021-Broken Access Control",
                "severity": "LOW",
                "is_vulnerable": True,
                "confidence_score": 1.0,
                "findings": "The uploaded file is not a valid JSON.",
                "mitigation_steps": "Ensure the file is a valid JSON.",
                "evidence_snippet": content[:100]
            })

        return {"results": results}

    def _scan_recursive(self, data: Any, results: List[Dict[str, Any]], path: str = "$"):
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}"
                self._check_value(key, value, current_path, results)
                self._scan_recursive(value, results, current_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                self._scan_recursive(item, results, current_path)

    def _check_value(self, key: str, value: Any, path: str, results: List[Dict[str, Any]]):
        val_str = str(value)
        
        # Check for API keys/tokens
        if self.patterns["api_key"].search(val_str) or self.patterns["api_key"].search(key):
             results.append({
                "name": "Exposed API Key/Token",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "severity": "CRITICAL",
                "is_vulnerable": True,
                "confidence_score": 0.8,
                "findings": f"Potential API key or token found at {path}.",
                "mitigation_steps": "Rotate the credential and use environment variables/secret managers.",
                "evidence_snippet": f"Key: {key}, Path: {path}"
            })

        # Check for prompt injection patterns
        if self.patterns["prompt_injection"].search(val_str):
            results.append({
                "name": "Prompt Injection Pattern",
                "owasp": "LLM01: Prompt Injection",
                "severity": "HIGH",
                "is_vulnerable": True,
                "confidence_score": 0.9,
                "findings": f"Prompt injection pattern detected at {path}.",
                "mitigation_steps": "Implement robust input validation and use system-level constraints.",
                "evidence_snippet": val_str[:100]
            })

        # Check for unsafe prompts
        if self.patterns["unsafe_prompt"].search(val_str):
            results.append({
                "name": "Unsafe LLM Prompt",
                "owasp": "LLM02: Insecure Output Handling",
                "severity": "MEDIUM",
                "is_vulnerable": True,
                "confidence_score": 0.7,
                "findings": f"Potentially unsafe or harmful prompt content found at {path}.",
                "mitigation_steps": "Apply content filtering and safety guardrails.",
                "evidence_snippet": val_str[:100]
            })

        # Check for insecure agent instructions
        if self.patterns["insecure_agent"].search(val_str):
            results.append({
                "name": "Insecure Agent Instructions",
                "owasp": "LLM07: Insecure Plugin Design",
                "severity": "HIGH",
                "is_vulnerable": True,
                "confidence_score": 0.8,
                "findings": f"Insecure agent instructions (e.g., shell execution) detected at {path}.",
                "mitigation_steps": "Restrict agent permissions and use sandboxed environments.",
                "evidence_snippet": val_str[:100]
            })

class CSVScanner(FileScanner):
    """
    Scanner for CSV files.
    Detects: credentials in columns, insecure URLs, authentication tokens, exposed secrets.
    """
    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        content = target or (context.get("content") if context else "")
        results = []
        
        try:
            f = io.StringIO(content)
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                for key, value in row.items():
                    self._check_cell(key, value, i, results)
        except Exception as e:
            results.append({
                "name": "CSV Parsing Error",
                "owasp": "A01:2021-Broken Access Control",
                "severity": "LOW",
                "is_vulnerable": True,
                "confidence_score": 1.0,
                "findings": f"Error parsing CSV: {str(e)}",
                "mitigation_steps": "Ensure the file is a valid CSV with headers.",
                "evidence_snippet": content[:100]
            })

        return {"results": results}

    def _check_cell(self, header: str, value: Any, row_index: int, results: List[Dict[str, Any]]):
        val_str = str(value)
        header_str = str(header)
        
        # Check for credentials/secrets
        if self.patterns["api_key"].search(val_str) or self.patterns["api_key"].search(header_str):
            results.append({
                "name": "Exposed Credential in CSV",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "severity": "CRITICAL",
                "is_vulnerable": True,
                "confidence_score": 0.8,
                "findings": f"Credential found in column '{header}' at row {row_index+1}.",
                "mitigation_steps": "Remove sensitive credentials from CSV files. Use secure storage.",
                "evidence_snippet": f"Column: {header}, Row: {row_index+1}"
            })

        # Check for insecure URLs
        if self.patterns["url"].search(val_str):
            if "http://" in val_str.lower():
                results.append({
                    "name": "Insecure HTTP URL",
                    "owasp": "A02:2021-Cryptographic Failures",
                    "severity": "MEDIUM",
                    "is_vulnerable": True,
                    "confidence_score": 1.0,
                    "findings": f"Insecure HTTP URL found in column '{header}' at row {row_index+1}.",
                    "mitigation_steps": "Use HTTPS instead of HTTP for all URLs.",
                    "evidence_snippet": val_str[:100]
                })
