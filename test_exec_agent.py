import sys
import os
import asyncio

sys.path.append(os.getcwd())
from backend.agents.core.execution_agent import ExecutionAgent
from backend.agents.registry import registry
from backend.agents.plugins.api_advanced_scanners import AdvancedBOLAScanner

async def test_execution():
    registry.register_scanner(AdvancedBOLAScanner)
    agent = ExecutionAgent("test_exec")
    
    # 1. Test Vulnerable Target
    target_vuln = "http://localhost:9001/api/v1/users/2"
    rule_bola = {"id": "1", "name": "BOLA", "owasp": "API01"}
    
    print(f"Testing vulnerable target: {target_vuln}")
    out = await agent.process({
        "target": target_vuln,
        "rule": rule_bola,
        "scan_id": "test"
    })
    for r in out.get("results", []):
        print(f"BOLA Vuln: {r.get('is_vulnerable')}")

    # 2. Test Secure Target (e.g. arbitrary site that returns 200 but shouldn't be vulnerable)
    # Actually, let's just use an endpoint we know returns 200 for other reasons or a public endpoint.
    # Like the root endpoint of mock_targets:
    target_secure = "http://localhost:9001/"
    print(f"\nTesting secure (or public) target: {target_secure}")
    out = await agent.process({
        "target": target_secure,
        "rule": rule_bola,
        "scan_id": "test"
    })
    for r in out.get("results", []):
        print(f"BOLA Vuln: {r.get('is_vulnerable')}")

if __name__ == "__main__":
    asyncio.run(test_execution())
