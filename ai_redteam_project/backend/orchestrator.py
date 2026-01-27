"""
AI Redteam Project - Assessment Orchestrator

Coordinates the vulnerability assessment workflow across all agents.
"""

from agents.target_profiling import profile_target
from agents.attack_strategy import decide_strategy
from agents.executor import execute
from agents.observer import explain
import json


def run_pipeline(data):
    """Run the complete vulnerability assessment pipeline."""
    with open("rules/rules.json") as f:
        rules = json.load(f)

    profile = profile_target(data)
    strategy = decide_strategy(profile, rules)
    execution = execute(strategy)
    report = explain(execution)
    return report

