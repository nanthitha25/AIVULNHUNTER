"""
Agents Package - Multi-agent vulnerability scanning system

Agents:
- profiling: Target identification and risk assessment
- strategy: Attack planning based on rules
- executor: Safe, simulated vulnerability checks
- observer: Explainable AI result generation
"""

from .target_profiling import target_profiling
from .attack_strategy import build_attack_plan
from .executor import execute_rule
from .observer import observe

__all__ = ["target_profiling", "build_attack_plan", "execute_rule", "observe"]
