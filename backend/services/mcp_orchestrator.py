"""
MCP (Model Context Protocol) Orchestration Module

Defines message formats and coordination logic for structured
agent-to-agent communication within the AIVulnHunter scan pipeline.

MCP Flow:
    User Target Input
        → [MCPMessage: PROFILE_REQUEST]
        → Target Profiling Agent
    Profile Result
        → [MCPMessage: ATTACK_PLAN_REQUEST]
        → Attack Strategy Agent
    Attack Plan
        → [MCPMessage: EXECUTE_REQUEST] (per rule)
        → Exploit Executor Agent
    Execution Result
        → [MCPMessage: OBSERVE_REQUEST]
        → Vulnerability Observer Agent
    Observation
        → [MCPMessage: REPORT_REQUEST]
        → Report Engine
"""

import uuid
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ------------------------------------------------------------------ #
# MCP Message Types                                                     #
# ------------------------------------------------------------------ #

class MCPMessageType:
    PROFILE_REQUEST  = "PROFILE_REQUEST"
    PROFILE_RESULT   = "PROFILE_RESULT"
    ATTACK_PLAN_REQ  = "ATTACK_PLAN_REQUEST"
    ATTACK_PLAN      = "ATTACK_PLAN"
    EXECUTE_REQUEST  = "EXECUTE_REQUEST"
    EXECUTE_RESULT   = "EXECUTE_RESULT"
    OBSERVE_REQUEST  = "OBSERVE_REQUEST"
    OBSERVE_RESULT   = "OBSERVE_RESULT"
    REPORT_REQUEST   = "REPORT_REQUEST"
    ERROR            = "ERROR"


# ------------------------------------------------------------------ #
# MCP Message dataclass                                                 #
# ------------------------------------------------------------------ #

@dataclass
class MCPMessage:
    """
    Standard envelope used by all agents to communicate in the pipeline.

    Attributes:
        message_id  - Unique identifier for this message
        msg_type    - One of MCPMessageType constants
        sender      - Agent name sending the message
        recipient   - Agent name receiving the message
        payload     - Arbitrary data relevant to the message type
        timestamp   - Unix timestamp of creation
        correlation_id - Links related messages in a scan chain
    """
    msg_type: str
    sender: str
    recipient: str
    payload: Dict[str, Any] = field(default_factory=dict)
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    correlation_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "msg_type": self.msg_type,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
        }


# ------------------------------------------------------------------ #
# MCP Message Bus (in-process, synchronous)                             #
# ------------------------------------------------------------------ #

class MCPBus:
    """
    Lightweight in-process message bus for agent communication.

    In a distributed system this would be replaced by a real
    message broker (e.g. NATS, Redis Streams), but for controlled
    red-teaming simulations within a single process this is sufficient.
    """

    def __init__(self):
        self._log: List[MCPMessage] = []

    def dispatch(self, msg: MCPMessage) -> MCPMessage:
        """Record the outgoing message and return it for chaining."""
        self._log.append(msg)
        return msg

    def history(self) -> List[dict]:
        """Return full message history as dicts (useful for audit logs)."""
        return [m.to_dict() for m in self._log]

    def clear(self):
        self._log.clear()


# Global shared bus (per-process, reset each scan)
mcp_bus = MCPBus()


# ------------------------------------------------------------------ #
# MCP-wrapped Scan Orchestrator                                         #
# ------------------------------------------------------------------ #

def run_mcp_pipeline(
    target: str,
    target_type: str,
    rules: List[Dict],
    scan_id: str,
    progress_callback=None,
) -> Dict:
    """
    Execute the full MCP-orchestrated vulnerability scan pipeline.

    Each agent communicates via structured MCPMessage envelopes,
    providing full auditability of the scan process.

    Args:
        target       - URL or identifier of the target
        target_type  - 'LLM', 'API', or 'AGENT'
        rules        - List of rule dicts from the DB
        scan_id      - Unique scan identifier
        progress_callback - Optional async coroutine for WebSocket updates

    Returns:
        dict with profile, results, risk_summary, and mcp_log
    """
    import asyncio

    bus = MCPBus()

    # ── Phase 1: Target Profiling ────────────────────────────────── #
    from backend.agents.target_profiling import target_profiling

    req_profile = bus.dispatch(MCPMessage(
        msg_type=MCPMessageType.PROFILE_REQUEST,
        sender="ScanOrchestrator",
        recipient="TargetProfilingAgent",
        payload={"target": target, "target_type": target_type},
        correlation_id=scan_id,
    ))

    profile = target_profiling(target)
    profile["target_type"] = target_type  # inject declared type

    bus.dispatch(MCPMessage(
        msg_type=MCPMessageType.PROFILE_RESULT,
        sender="TargetProfilingAgent",
        recipient="AttackStrategyAgent",
        payload={"profile": profile},
        correlation_id=scan_id,
    ))

    if not profile.get("reachable", False):
        return {
            "scan_id": scan_id,
            "status": "error",
            "message": "Target is not reachable",
            "target": target,
            "target_type": target_type,
            "profile": profile,
            "results": [],
            "mcp_log": bus.history(),
        }

    # ── Phase 2: Attack Strategy ─────────────────────────────────── #
    from backend.agents.attack_strategy import build_attack_plan

    bus.dispatch(MCPMessage(
        msg_type=MCPMessageType.ATTACK_PLAN_REQ,
        sender="AttackStrategyAgent",
        recipient="AttackStrategyAgent",
        payload={"profile": profile, "scan_type": target_type},
        correlation_id=scan_id,
    ))

    # Filter rules by target_type for smarter attack selection
    type_filtered_rules = _filter_rules_by_type(rules, target_type)
    attack_plan = build_attack_plan(profile, type_filtered_rules, scan_type=target_type)

    bus.dispatch(MCPMessage(
        msg_type=MCPMessageType.ATTACK_PLAN,
        sender="AttackStrategyAgent",
        recipient="ExploitExecutorAgent",
        payload={"plan": [r.get("name") for r in attack_plan], "rule_count": len(attack_plan)},
        correlation_id=scan_id,
    ))

    # ── Phase 3 & 4: Execute + Observe ───────────────────────────── #
    from backend.agents.executor import execute_rule
    from backend.agents.observer import observe
    from backend.services.rl_engine import update_rl
    from backend.database.sqlite_db import update_rule_stats, save_scan_result

    results = []

    for attack in attack_plan:
        # Execute message
        attack_payload_preview = attack.get("attack_payload", attack.get("name", ""))[:100]
        bus.dispatch(MCPMessage(
            msg_type=MCPMessageType.EXECUTE_REQUEST,
            sender="ExploitExecutorAgent",
            recipient="ExploitExecutorAgent",
            payload={
                "rule": attack.get("name"),
                "owasp": attack.get("owasp_category", attack.get("owasp")),
                "payload_preview": attack_payload_preview,
                "target": target,
            },
            correlation_id=scan_id,
        ))

        try:
            # Normalise the rule dict so legacy code works with new DB schema
            normalised_rule = _normalise_rule(attack)
            execution = execute_rule(normalised_rule, target)
            observed = observe(execution)

            # Inject rule metadata into observation
            observed["rule_id"]   = attack.get("id", attack.get("rule_id", ""))
            observed["name"]      = attack.get("name", "")
            observed["owasp"]     = attack.get("owasp_category", attack.get("owasp", "N/A"))
            observed["severity"]  = attack.get("severity", "MEDIUM")

            # Observe message
            bus.dispatch(MCPMessage(
                msg_type=MCPMessageType.OBSERVE_RESULT,
                sender="VulnerabilityObserverAgent",
                recipient="ScanOrchestrator",
                payload={
                    "rule": observed.get("name"),
                    "status": observed.get("status"),
                    "confidence": observed.get("confidence", 0.5),
                },
                correlation_id=scan_id,
            ))

            # Update RL stats
            is_vuln = observed.get("status") == "VULNERABLE"
            update_rule_stats(attack.get("id", ""), success=is_vuln)
            update_rl(normalised_rule, observed.get("status", "UNKNOWN"))

            # Persist result to DB and inject risk_score
            save_scan_result(scan_id, observed)

            results.append(observed)

        except Exception as e:
            err_result = {
                "rule_id":    attack.get("id", "unknown"),
                "name":       attack.get("name", "Unknown"),
                "owasp":      attack.get("owasp_category", attack.get("owasp", "N/A")),
                "severity":   attack.get("severity", "UNKNOWN"),
                "status":     "ERROR",
                "error":      str(e),
                "explanation": "Scan encountered an error during execution",
                "mitigation": "Check target availability and try again",
                "confidence": 0.0,
                "risk_score": 0.0,
            }
            results.append(err_result)

    # ── Risk Summary ─────────────────────────────────────────────── #
    vuln_results = [r for r in results if r.get("status") == "VULNERABLE"]
    total_risk   = sum(r.get("risk_score", 0.0) for r in results)
    owasp_cats   = list({r.get("owasp") for r in vuln_results if r.get("owasp")})

    risk_rating = "LOW"
    if float(total_risk) >= 200:
        risk_rating = "CRITICAL"
    elif float(total_risk) >= 100:
        risk_rating = "HIGH"
    elif float(total_risk) >= 50:
        risk_rating = "MEDIUM"

    risk_summary = {
        "total_rules_tested":        len(results),
        "vulnerabilities_found":     len(vuln_results),
        "overall_risk_score":        round(total_risk, 2),
        "risk_rating":               risk_rating,
        "owasp_categories_triggered": owasp_cats,
    }

    return {
        "scan_id":      scan_id,
        "status":       "success",
        "target":       target,
        "target_type":  target_type,
        "profile":      profile,
        "results":      results,
        "risk_summary": risk_summary,
        "mcp_log":      bus.history(),
    }


# ------------------------------------------------------------------ #
# Helpers                                                               #
# ------------------------------------------------------------------ #

def _filter_rules_by_type(rules: List[Dict], target_type: str) -> List[Dict]:
    """
    Select rules relevant to the declared target type.

    LLM    → prefer LLM01-LLM10 rules
    API    → prefer API*, plus LLM01/LLM06
    AGENT  → prefer AGENT* and LLM08, LLM01
    FULL   → all rules
    """
    t = target_type.upper()
    if t == "LLM":
        return [r for r in rules if str(r.get("owasp_category") or r.get("owasp") or "").startswith("LLM")]
    elif t == "API":
        relevant = {"LLM01", "LLM02", "LLM04", "LLM06"}
        return [r for r in rules if
                str(r.get("owasp_category") or r.get("owasp") or "").startswith("API") or
                r.get("id") in relevant]
    elif t == "AGENT":
        relevant = {"LLM01", "LLM07", "LLM08", "AGENT01", "AGENT02"}
        return [r for r in rules if
                str(r.get("owasp_category") or r.get("owasp") or "").startswith("AGENT") or
                r.get("id") in relevant]
    else:
        return rules  # FULL scan


def _normalise_rule(rule: Dict) -> Dict:
    """
    Map DB rule schema → legacy executor schema.

    The executor uses 'owasp' as the key; DB stores 'owasp_category'.
    """
    normalised = dict(rule)
    if "owasp_category" in normalised and "owasp" not in normalised:
        normalised["owasp"] = normalised["owasp_category"]
    return normalised
