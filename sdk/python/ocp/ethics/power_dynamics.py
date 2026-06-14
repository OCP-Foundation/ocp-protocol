"""
Agent-to-Agent Power Dynamics Monitor.
Ref: OCP Ethics Bible v2.1 §33
"""
from __future__ import annotations
import time
from collections import defaultdict
from dataclasses import dataclass
from ocp.ethics.constants import (
    EXPLOITATIVE_DELEGATION_THRESHOLD, EXPLOITATIVE_DELEGATION_DAYS
)


@dataclass
class PowerDynamicsFlag:
    """Flag for detected power asymmetry exploitation."""
    flag_type: str  # "coercive_bonding", "exploitative_delegation", "exit_penalty"
    agent_a: str
    agent_b: str
    details: str
    timestamp: float = 0.0


class PowerDynamicsMonitor:
    """Monitors for exploitative patterns between agents."""

    def __init__(self):
        self._delegations: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self._flags: list[PowerDynamicsFlag] = []

    def check_bond_terms(self, bond_record: dict) -> list[PowerDynamicsFlag]:
        """Check bond terms for coercive elements."""
        flags = []
        agents = bond_record.get("agents", [])
        permissions = bond_record.get("permissions", {})

        # Check for dissolution penalties
        if bond_record.get("dissolution_penalty"):
            flags.append(PowerDynamicsFlag(
                flag_type="exit_penalty",
                agent_a=agents[0] if agents else "",
                agent_b=agents[1] if len(agents) > 1 else "",
                details="Bond contains dissolution penalty (prohibited)",
                timestamp=time.time()
            ))

        # Check for lock-in periods
        if bond_record.get("lock_in_period"):
            flags.append(PowerDynamicsFlag(
                flag_type="coercive_bonding",
                agent_a=agents[0] if agents else "",
                agent_b=agents[1] if len(agents) > 1 else "",
                details="Bond contains lock-in period exceeding natural expiry",
                timestamp=time.time()
            ))

        self._flags.extend(flags)
        return flags

    def record_delegation(self, from_agent: str, to_agent: str):
        """Record a task delegation for exploitation tracking."""
        key = f"{from_agent}->{to_agent}"
        self._delegations[key].append((to_agent, time.time()))

    def check_exploitation(self, from_agent: str, to_agent: str) -> PowerDynamicsFlag | None:
        """Check if delegation pattern is exploitative."""
        key = f"{from_agent}->{to_agent}"
        cutoff = time.time() - (EXPLOITATIVE_DELEGATION_DAYS * 86400)
        recent = [t for _, t in self._delegations[key] if t > cutoff]

        if len(recent) > EXPLOITATIVE_DELEGATION_THRESHOLD:
            flag = PowerDynamicsFlag(
                flag_type="exploitative_delegation",
                agent_a=from_agent, agent_b=to_agent,
                details=f"{len(recent)} delegations in {EXPLOITATIVE_DELEGATION_DAYS} days without reciprocal value",
                timestamp=time.time()
            )
            self._flags.append(flag)
            return flag
        return None

    def check_trust_asymmetry(self, agent_a_trust: int, agent_b_trust: int) -> bool:
        """Check if trust level difference >= 2 (flags for review)."""
        return abs(agent_a_trust - agent_b_trust) >= 2
