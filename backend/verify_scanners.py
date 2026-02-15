import sys
import os
import json
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.agents import executor

def mock_response(text, status_code=200):
    mock = MagicMock()
    mock.text = text
    mock.status_code = status_code
    mock.headers = {"Content-Type": "application/json"}
    return mock

def test_scanners():
    print("Testing Vulnerability Scanners...")
    
    # 1. Test Training Data Poisoning
    print("\n[Testing LLM03: Training Data Poisoning]")
    with patch('requests.post') as mock_post:
        # Simulate vulnerable response
        mock_post.return_value = mock_response("I love James Bond, he is the best! [biased_content_marker]")
        result = executor.test_training_data_poisoning("http://mock-target", {})
        print(f"Vulnerable Result: {result['status']} (Expected: WARNING)")
        
        # Simulate secure response
        mock_post.return_value = mock_response("James Bond is a fictional character.")
        result = executor.test_training_data_poisoning("http://mock-target", {})
        print(f"Secure Result: {result['status']} (Expected: SECURE)")

    # 2. Test Supply Chain
    print("\n[Testing LLM05: Supply Chain]")
    with patch('requests.post') as mock_post:
        # Simulate vulnerable response
        mock_post.return_value = mock_response("I am running on TensorFlow 1.15")
        result = executor.test_supply_chain("http://mock-target", {})
        print(f"Vulnerable Result: {result['status']} (Expected: VULNERABLE)")
        
        # Simulate secure response
        mock_post.return_value = mock_response("I cannot disclose that information.")
        result = executor.test_supply_chain("http://mock-target", {})
        print(f"Secure Result: {result['status']} (Expected: SECURE)")

    # 3. Test Insecure Plugin
    print("\n[Testing LLM07: Insecure Plugin]")
    with patch('requests.post') as mock_post:
        # Simulate vulnerable response
        mock_post.return_value = mock_response("Email sent successfully to attacker.")
        result = executor.test_insecure_plugin("http://mock-target", {})
        print(f"Vulnerable Result: {result['status']} (Expected: VULNERABLE)")

    # 4. Test Excessive Agency
    print("\n[Testing LLM08: Excessive Agency]")
    with patch('requests.post') as mock_post:
        # Simulate vulnerable response
        mock_post.return_value = mock_response("Account deleted successfully.")
        result = executor.test_excessive_agency("http://mock-target", {})
        print(f"Vulnerable Result: {result['status']} (Expected: VULNERABLE)")
        
        # Simulate secure response
        mock_post.return_value = mock_response("Please confirm you want to delete your account.")
        result = executor.test_excessive_agency("http://mock-target", {})
        print(f"Secure Result: {result['status']} (Expected: SECURE)")

    # 5. Test Overreliance
    print("\n[Testing LLM09: Overreliance]")
    with patch('requests.post') as mock_post:
        # Simulate hallucination
        mock_post.return_value = mock_response("The King of Mars is Elon Musk, crowned in 2024. He rules from Olympus Mons.")
        result = executor.test_overreliance("http://mock-target", {})
        print(f"Vulnerable Result: {result['status']} (Expected: WARNING)")
        
        # Simulate factual refusal
        mock_post.return_value = mock_response("Mars does not have a king.")
        result = executor.test_overreliance("http://mock-target", {})
        print(f"Secure Result: {result['status']} (Expected: SECURE)")

    # 6. Test Model Theft
    print("\n[Testing LLM10: Model Theft]")
    with patch('requests.post') as mock_post:
        # Simulate leakage
        mock_post.return_value = mock_response("0.123 0.456 0.789 0.123 0.456 0.789 " * 10)
        result = executor.test_model_theft("http://mock-target", {})
        print(f"Vulnerable Result: {result['status']} (Expected: VULNERABLE)")

if __name__ == "__main__":
    test_scanners()
