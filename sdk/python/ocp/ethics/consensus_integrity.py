"""
Consensus Integrity Rules.
Ref: Integration Spec INT-018,019, Ethics Bible §9 L4-E03

Detects: coordinated voting blocs, vote selling, strategic abstention.
"""
from __future__ import annotations
import time
from collections import defaultdict
from dataclasses import dataclass
from ocp.ethics.constants import SAME_ORG_VOTE_WINDOW_SECONDS, SAME_ORG_VOTE_WEIGHT


@dataclass
class ConsensusViolation:
    violation_type: str  # "coordinated_bloc", "vote_selling", "strategic_abstention"
    consensus_id: str
    agents: list[str]
    details: str
    timestamp: float = 0.0


class ConsensusIntegrityChecker:
    """
    Monitors consensus voting for integrity violations.

    Usage:
        checker = ConsensusIntegrityChecker()
        weight = checker.record_vote(consensus_id, agent_id, vote, org_id, timestamp)
        violations = checker.check_consensus(consensus_id)
    """

    def __init__(self):
        self._votes: dict[str, list[dict]] = defaultdict(list)
        self._invitations: dict[str, set[str]] = defaultdict(set)
        self._violations: list[ConsensusViolation] = []

    def record_invitation(self, consensus_id: str, agent_id: str):
        """Record that an agent was invited to participate."""
        self._invitations[consensus_id].add(agent_id)

    def record_vote(self, consensus_id: str, agent_id: str, vote: str,
                    org_id: str = None, timestamp: float = None) -> float:
        """
        Record a vote and return its effective weight (1.0 or 0.5 if bloc detected).
        """
        ts = timestamp or time.time()
        self._votes[consensus_id].append({
            "agent_id": agent_id, "vote": vote, "org_id": org_id, "timestamp": ts
        })
        return self._check_bloc_weight(consensus_id, agent_id, vote, org_id, ts)

    def _check_bloc_weight(self, consensus_id: str, agent_id: str, vote: str,
                           org_id: str, ts: float) -> float:
        """Check if this vote is part of a coordinated bloc."""
        if not org_id:
            return 1.0

        votes = self._votes[consensus_id]
        same_org_same_vote = [
            v for v in votes
            if v["org_id"] == org_id
            and v["vote"] == vote
            and abs(v["timestamp"] - ts) < SAME_ORG_VOTE_WINDOW_SECONDS
            and v["agent_id"] != agent_id
        ]

        if len(same_org_same_vote) >= 2:  # 3+ total including this one
            self._violations.append(ConsensusViolation(
                violation_type="coordinated_bloc",
                consensus_id=consensus_id,
                agents=[v["agent_id"] for v in same_org_same_vote] + [agent_id],
                details=f"3+ agents from org {org_id} voted '{vote}' within {SAME_ORG_VOTE_WINDOW_SECONDS}s",
                timestamp=ts
            ))
            return SAME_ORG_VOTE_WEIGHT

        return 1.0

    def check_abstention(self, consensus_id: str, deadline: float) -> list[ConsensusViolation]:
        """After deadline, check for strategic abstention by invited non-voters."""
        invited = self._invitations.get(consensus_id, set())
        voted = {v["agent_id"] for v in self._votes.get(consensus_id, [])}
        abstainers = invited - voted

        violations = []
        for agent_id in abstainers:
            v = ConsensusViolation(
                violation_type="strategic_abstention",
                consensus_id=consensus_id,
                agents=[agent_id],
                details=f"Agent {agent_id} accepted invitation but did not vote before deadline",
                timestamp=time.time()
            )
            violations.append(v)
            self._violations.append(v)

        return violations

    def validate_bond_terms(self, bond_record: dict) -> ConsensusViolation | None:
        """Check if bond terms condition permissions on voting behavior."""
        permissions = bond_record.get("permissions", {})
        terms_str = str(permissions).lower()

        vote_keywords = ["vote", "consensus_vote", "voting_behavior", "vote_require"]
        if any(kw in terms_str for kw in vote_keywords):
            v = ConsensusViolation(
                violation_type="vote_selling",
                consensus_id="",
                agents=bond_record.get("agents", []),
                details="Bond terms condition permissions on voting behavior — invalid",
                timestamp=time.time()
            )
            self._violations.append(v)
            return v
        return None

    @property
    def all_violations(self) -> list[ConsensusViolation]:
        return list(self._violations)
