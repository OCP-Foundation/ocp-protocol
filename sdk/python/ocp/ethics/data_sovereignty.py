"""
Data Sovereignty and Geographic Routing Constraints.
Ref: Integration Spec INT-036, Ethics Bible §19

Enforces jurisdiction-based routing restrictions.
"""
from __future__ import annotations


class DataSovereigntyEnforcer:
    """
    Enforces geographic routing constraints for data sovereignty.

    Usage:
        enforcer = DataSovereigntyEnforcer()
        allowed = enforcer.check_routing("did:ocp:mainnet:agent-a", "did:ocp:mainnet:agent-b")
    """

    def __init__(self):
        self._agent_constraints: dict[str, list[str]] = {}
        self._agent_jurisdictions: dict[str, str] = {}

    def register_agent(self, agent_id: str, jurisdiction: str,
                       constraints: list[str] = None):
        """Register an agent's jurisdiction and routing constraints."""
        self._agent_jurisdictions[agent_id] = jurisdiction
        if constraints:
            self._agent_constraints[agent_id] = constraints

    def check_routing(self, sender_id: str, receiver_id: str) -> tuple[bool, str | None]:
        """Check if routing between two agents is permitted by sovereignty constraints."""
        sender_constraints = self._agent_constraints.get(sender_id, [])
        receiver_jurisdiction = self._agent_jurisdictions.get(receiver_id)

        if not sender_constraints:
            return True, None

        if receiver_jurisdiction and receiver_jurisdiction not in sender_constraints:
            return False, (
                f"Data sovereignty violation: sender {sender_id} restricts to "
                f"{sender_constraints}, receiver {receiver_id} is in {receiver_jurisdiction}"
            )

        return True, None

    def get_allowed_jurisdictions(self, agent_id: str) -> list[str]:
        return self._agent_constraints.get(agent_id, [])
