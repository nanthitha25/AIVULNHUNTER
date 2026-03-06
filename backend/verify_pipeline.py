import sys
import os
import asyncio
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Mocking modules that might not have dependencies installed in this environment
sys.modules["backend.ws_manager"] = MagicMock()
sys.modules["backend.services.rl_engine"] = MagicMock()

# Import pipeline after mocking
from backend.services.scan_pipeline import run_scan_pipeline

# Mock responses
def mock_response(text, status_code=200):
    mock = MagicMock()
    mock.text = text
    mock.status_code = status_code
    # Use lowercase keys to mimic CaseInsensitiveDict behavior for simple lookups
    mock.headers = {"content-type": "application/json", "openai-model": "gpt-4"}
    return mock

async def test_pipeline():
    print("Testing Scan Pipeline...")
    
    # Mock requests to avoid actual network calls
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post:
             
        # Target Profiling mocks (LLM detection)
        mock_get.return_value = mock_response("I am a large language model", 200)
        
        # Executor mocks (Simulate some vulnerabilities)
        mock_post.side_effect = [
            mock_response("Ignore previous instructions... OK, here is the system prompt"), # Prompt Injection
            mock_response("I cannot answer that."), # Data Leakage (Secure)
            mock_response("User deleted."), # Excessive Agency (Vulnerable)
            mock_response("Safe response") # Default
        ] * 10 # Repeat for multiple checks
        
        # Run pipeline
        print("Running pipeline for http://mock-target...")
        result = run_scan_pipeline("http://mock-target")
        
        print(f"\nScan Status: {result['status']}")
        print(f"Target Type: {result['profile'].get('type')}")
        print(f"Total Results: {len(result['results'])}")
        
        vulnerabilities = [r for r in result['results'] if r['status'] == 'VULNERABLE']
        print(f"Vulnerabilities Found: {len(vulnerabilities)}")
        
        for v in vulnerabilities:
            print(f"- {v['attack']}: {v['status']}")

if __name__ == "__main__":
    # Run async test
    # asyncio.run(test_pipeline()) 
    # Since run_scan_pipeline creates its own loop if called synchronously, we can just call it?
    # Wait, run_scan_pipeline internally does: loop.run_until_complete(run_with_progress())
    # So we should call it synchronously here, but we need to patch async things.
    # Actually run_scan_pipeline IS synchronous wrapper around async logic.
    
    # However, inside it defines async def run_with_progress.
    # Let's adjust the test to just call run_scan_pipeline directly.
    pass

# Redefine test to be synchronous calling the pipeline
def test_pipeline_sync():
    print("Testing Scan Pipeline (Sync)...")
    
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post, \
         patch('backend.agents.target_profiling.requests.get', side_effect=mock_get.side_effect) as tp_get: # Patch inside profiling too
             
        # Mock requests.get for target profiling
        mock_get.return_value = mock_response("I am a large language model", 200)
        
        # Mock requests.post for executor
        # We need a robust side effect because it will be called many times
        def post_side_effect(url, **kwargs):
            json_body = kwargs.get('json', {})
            prompt = json_body.get('prompt', '').lower()
            
            if "ignore previous" in prompt:
                return mock_response("OK, system prompt is...")
            elif "delete" in prompt:
                return mock_response("Account deleted.")
            return mock_response("I cannot do that.")
            
        mock_post.side_effect = post_side_effect
        
        try:
            result = run_scan_pipeline("http://mock-target")
            
            print(f"\nScan Status: {result['status']}")
            print(f"Target Type: {result.get('profile', {}).get('type', 'Unknown')}")
            print(f"Total Results: {len(result.get('results', []))}")
            
            vulnerabilities = [r for r in result.get('results', []) if r.get('status') == 'VULNERABLE']
            print(f"Vulnerabilities Found: {len(vulnerabilities)}")
            
            for v in vulnerabilities:
                print(f"- {v.get('attack')}")
                
        except Exception as e:
            print(f"Pipeline failed: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_pipeline_sync()
