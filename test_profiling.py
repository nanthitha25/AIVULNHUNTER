import sys
import os
sys.path.insert(0, os.path.abspath('.'))
from backend.agents.target_profiling import target_profiling

targets = [
    "http://localhost:9001/api/v1/users/1",
    "http://localhost:8080/v1/chat/completions",
    "http://localhost:9001/agent/execute"
]
for t in targets:
    print(f"Target: {t}")
    print(target_profiling(t))
    print("-" * 50)
