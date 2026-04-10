"""
tests/test_assistant.py

Unit + integration tests for the AivulnHunter AI Assistant module.
Run with:  pytest tests/test_assistant.py -v
"""

import json
import pytest
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CLAUDE_MODEL  = "claude"
GEMINI_MODEL  = "gemini"
FALLBACK_MSG  = "AI service temporarily unavailable. Please verify API keys and internet connection."


def _claude_ok(answer: str):
    """Return a mock that makes ask_claude succeed."""
    return patch("backend.ai.assistant.ask_claude", return_value=answer)


def _claude_fail(exc: Exception):
    """Return a mock that makes ask_claude raise exc every call."""
    return patch("backend.ai.assistant.ask_claude", side_effect=exc)


def _gemini_ok(answer: str):
    return patch("backend.ai.assistant.ask_gemini", return_value=answer)


def _gemini_fail(exc: Exception):
    return patch("backend.ai.assistant.ask_gemini", side_effect=exc)


# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

from backend.ai.assistant import ask_assistant


# ===========================================================================
# 2. Unit tests — ask_assistant (happy paths)
# ===========================================================================

class TestAskAssistantHappyPath:
    def test_claude_used_by_default(self):
        with _claude_ok("BOLA is..."), _gemini_ok("fallback"):
            result = ask_assistant("Explain BOLA vulnerability")
        assert result["model_used"] == CLAUDE_MODEL
        assert "BOLA" in result["answer"] or result["answer"] == "BOLA is..."

    def test_returns_structured_json(self):
        with _claude_ok("Answer text"):
            result = ask_assistant("What is SSRF?")
        assert "model_used" in result
        assert "answer" in result
        # ensure it is JSON-serialisable
        json.dumps(result)

    def test_explain_bola(self):
        with _claude_ok("BOLA stands for Broken Object Level Authorization..."):
            result = ask_assistant("Explain BOLA vulnerability")
        assert result["model_used"] == CLAUDE_MODEL
        assert len(result["answer"]) > 0

    def test_explain_prompt_injection(self):
        with _claude_ok("Prompt injection occurs when..."):
            result = ask_assistant("Explain Prompt Injection")
        assert result["model_used"] == CLAUDE_MODEL

    def test_explain_scan_results(self):
        scan_ctx = "Found: SQL Injection on /login endpoint, CVSS 9.8"
        with _claude_ok("The scan found a critical SQL injection..."):
            result = ask_assistant("Explain scan results", context=scan_ctx)
        assert result["model_used"] == CLAUDE_MODEL


# ===========================================================================
# 3. Fallback behaviour
# ===========================================================================

class TestFallbackToGemini:
    def test_error_triggers_gemini(self):
        err = RuntimeError("503 service unavailable")
        with _claude_fail(err), _gemini_ok("Gemini answer"):
            result = ask_assistant("What is BOLA?")
        assert result["model_used"] == GEMINI_MODEL
        assert result["answer"] == "Gemini answer"

    def test_both_fail_returns_fallback(self):
        with _claude_fail(Exception("503")), _gemini_fail(Exception("quota")):
            result = ask_assistant("Explain RCE")
        assert result["model_used"] == "none"
        assert result["answer"] == FALLBACK_MSG


# ===========================================================================
# 5. FastAPI route tests
# ===========================================================================

@pytest.fixture
def fastapi_app():
    from backend.main import app
    return app


@pytest.fixture
def client(fastapi_app):
    from fastapi.testclient import TestClient
    return TestClient(fastapi_app)


class TestFastAPIRoute:
    def test_valid_request(self, client):
        with _claude_ok("BOLA explanation"):
            resp = client.post(
                "/api/v1/assistant",
                json={"question": "Explain BOLA vulnerability"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["model_used"] == CLAUDE_MODEL
        assert data["answer"] == "BOLA explanation"

    def test_with_scan_context(self, client):
        with _claude_ok("Scan explanation"):
            resp = client.post(
                "/api/v1/assistant",
                json={
                    "question": "Explain scan results",
                    "scan_context": "SQL injection found on /login",
                },
            )
        assert resp.status_code == 200

    def test_missing_question_returns_422(self, client):
        # FastAPI returns 422 for pydantic validation errors
        resp = client.post("/api/v1/assistant", json={})
        assert resp.status_code == 422

    def test_empty_question_returns_400(self, client):
        resp = client.post("/api/v1/assistant", json={"question": "   "})
        assert resp.status_code == 400

    def test_both_models_fail_returns_200_with_fallback(self, client):
        # We decided to return 200 with the fallback message in the route update
        with _claude_fail(Exception("503")), _gemini_fail(Exception("quota")):
            resp = client.post(
                "/api/v1/assistant",
                json={"question": "Explain RCE"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert FALLBACK_MSG in (data.get("answer") or "")
