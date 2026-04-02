import sys
import os
import asyncio

# Ensure backend can be imported
sys.path.append(os.getcwd())

from backend.agents.plugins.api_advanced_scanners import AdvancedBOLAScanner

async def validate_contract():
    scanner = AdvancedBOLAScanner(agent_id="TestScanner", config={})
    
    # We need mock_targets running for this to be a real scan, 
    # but the logic contract is what matters.
    target = "http://localhost:8081/api/v1/users/1"
    
    print(f"Executing scan with {scanner.__class__.__name__}...")
    try:
        raw_output = await scanner.scan(target)
        print("\nRaw Scanner Output:")
        import json
        print(json.dumps(raw_output, indent=2))
        
        expected_keys = {
            "is_vulnerable", 
            "severity", 
            "confidence_score", 
            "findings", 
            "mitigation_steps", 
            "evidence_snippet"
        }
        
        actual_keys = set(raw_output.keys())
        
        missing = expected_keys - actual_keys
        extra = actual_keys - expected_keys
        
        if missing:
            print(f"❌ MISSING FIELDS: {missing}")
        if extra:
            print(f"❌ EXTRA FIELDS: {extra}")
            
        if not missing and not extra:
            print("\n✅ SUCCESS: Scanner strictly follows the Phase 1 contract.")
            
    except Exception as e:
        print(f"❌ ERROR: Scan execution failed: {e}")

if __name__ == "__main__":
    asyncio.run(validate_contract())
