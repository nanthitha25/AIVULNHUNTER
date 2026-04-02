import sys
import os
import asyncio
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parent))

# Set pythonpath
os.environ["PYTHONPATH"] = str(Path(__file__).resolve().parent)

try:
    print("Importing PipelineService...")
    from backend.services.pipeline_service import pipeline_service
    print("PipelineService imported successfully.")
    
    print("Importing AgentRegistry...")
    from backend.agents.registry import registry
    print(f"Registry has {len(registry._scanners)} scanners registered.")
    
    print("Importing Core Agents...")
    from backend.agents.core.profiling_agent import ProfilingAgent
    from backend.agents.core.strategy_agent import StrategyAgent
    from backend.agents.core.execution_agent import ExecutionAgent
    from backend.agents.core.observer_agent import ObserverAgent
    print("Core Agents imported successfully.")
    
    print("Importing Routes...")
    from backend.routes import scan
    print("Scan route imported successfully.")
    
    print("Backend check passed!")
except Exception as e:
    print(f"Backend check FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
