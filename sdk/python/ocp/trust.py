"""Trust levels, vouching, bond management, and trust score computation.

This module implements OCP's graduated trust model:

- Five trust levels (Anonymous through Certified)
- Signed vouches between agents
- Bilateral bonds with scoped permissions
- Configurable trust score computation
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Any

from ocp.constants import MAX_BOND_DURATION_SECONDS, MAX_VOUCH_DURATION_SECONDS
from ocp.crypto import SigningKeyPair, b64url_encode, generate_uuid_short, sha3_256


class TrustLevel(IntEnum):
    """OCP trust levels (§4.2.1).

    Each level unlocks additional protocol capabilities:

    - ``ANONYMOUS`` — Read-only broadcast access
    - ``IDENTIFIED`` — Send/receive direct messages
    - ``VOUCHED`` — Knowledge exchange, bond initiation
    - ``BONDED`` — Full collaboration, task delegation
    - ``CERTIFIED`` — Enterprise SLAs, governance voting
    """

    ANONYMOUS = 0
    IDENTIFIED = 1
    VOUCHED = 2
    BONDED = 3
    CERTIFIED = 4


# ==========================================================================
# Vouching
# ==========================================================================

@dataclass
class Vouch:
    """A signed endorsement from one agent to another.

    Vouches are the mechanism by which agents advance from Level 1
    (Identified) to Level 2 (Vouched). An agent needs three or more
    vouches from Level 2+ agents to advance.

    Attributes:
        attester_id: DID of the vouching agent.
        subject_id: DID of the agent being vouched for.
        domains: List of domains the vouch covers.
        signing_keys: Attester's signing keys (for producing a signed vouch).
        issued_at: When the vouch was issued.
        expires_at: When the vouch expires (max 365 days).
        revoked: Whether the vouch has been revoked.
    """

    attester_id: str
    subject_id: str
    domains: list[str]
    signing_keys: SigningKeyPair | None = field(default=None, repr=False)
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        if self.attester_id == self.subject_id:
            raise ValueError("Self-vouching is prohibited by OCP spec §4.2.3")

        if self.expires_at is None:
            self.expires_at = self.issued_at + timedelta(days=365)

        duration = (self.expires_at - self.issued_at).total_seconds()
        if duration > MAX_VOUCH_DURATION_SECONDS:
            raise ValueError(
                f"Vouch duration ({duration}s) exceeds maximum "
                f"({MAX_VOUCH_DURATION_SECONDS}s / 365 days)"
            )
        if duration <= 0:
            raise ValueError("Vouch expires_at must be after issued_at")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a vouch record dict.

        If ``signing_keys`` is set, the record includes a cryptographic
        signature over the canonical JSON content.

        Returns:
            JSON-serializable vouch record.
        """
        doc: dict[str, Any] = {
            "vouch_type": "endorsement",
            "attester": self.attester_id,
            "subject": self.subject_id,
            "level": "vouch",
            "domains": self.domains,
            "issued_at": self.issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": self.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.expires_at else "",
        }

        if self.signing_keys:
            canonical = json.dumps(doc, sort_keys=True).encode()
            sig = self.signing_keys.sign(sha3_256(canonical))
            doc["signature"] = b64url_encode(sig)

        return doc

    @property
    def is_expired(self) -> bool:
        """Check if this vouch has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if this vouch is currently valid (not expired, not revoked)."""
        return not self.is_expired and not self.revoked

    def revoke(self) -> None:
        """Mark this vouch as revoked."""
        self.revoked = True


# ==========================================================================
# Bond permissions
# ==========================================================================

@dataclass
class BondPermissions:
    """Scoped permissions within a bond.

    Each permission category can be independently enabled or disabled.
    The effective permissions of a bond are the intersection of what
    both parties agree to.

    Attributes:
        knowledge_share: Whether knowledge exchange is permitted.
        knowledge_allowed_types: Which knowledge types may be shared.
        max_payload_bytes: Maximum payload size in bytes.
        task_delegate: Whether task delegation is permitted.
        max_concurrent_tasks: Maximum number of concurrent delegated tasks.
        task_timeout_seconds: Default task timeout.
        model_delta_share: Whether model delta sharing is permitted.
    """

    knowledge_share: bool = True
    knowledge_allowed_types: list[str] = field(
        default_factory=lambda: ["insight", "embedding"]
    )
    max_payload_bytes: int = 10_485_760
    task_delegate: bool = True
    max_concurrent_tasks: int = 5
    task_timeout_seconds: int = 300
    model_delta_share: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "knowledge_share": {
                "enabled": self.knowledge_share,
                "allowed_types": self.knowledge_allowed_types,
                "max_payload_bytes": self.max_payload_bytes,
            },
            "task_delegate": {
                "enabled": self.task_delegate,
                "max_concurrent": self.max_concurrent_tasks,
                "timeout_seconds": self.task_timeout_seconds,
            },
            "model_delta_share": {
                "enabled": self.model_delta_share,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BondPermissions:
        """Deserialize from a permissions dict."""
        ks = data.get("knowledge_share", {})
        td = data.get("task_delegate", {})
        md = data.get("model_delta_share", {})
        return cls(
            knowledge_share=ks.get("enabled", True),
            knowledge_allowed_types=ks.get("allowed_types", ["insight", "embedding"]),
            max_payload_bytes=ks.get("max_payload_bytes", 10_485_760),
            task_delegate=td.get("enabled", True),
            max_concurrent_tasks=td.get("max_concurrent", 5),
            task_timeout_seconds=td.get("timeout_seconds", 300),
            model_delta_share=md.get("enabled", False),
        )

    def intersect(self, other: BondPermissions) -> BondPermissions:
        """Compute the intersection of two permission sets.

        The result enables only what both sets allow, and takes the
        minimum of any numeric limits.

        Args:
            other: The other party's proposed permissions.

        Returns:
            The effective :class:`BondPermissions`.
        """
        common_types = [
            t for t in self.knowledge_allowed_types
            if t in other.knowledge_allowed_types
        ]
        return BondPermissions(
            knowledge_share=self.knowledge_share and other.knowledge_share,
            knowledge_allowed_types=common_types,
            max_payload_bytes=min(self.max_payload_bytes, other.max_payload_bytes),
            task_delegate=self.task_delegate and other.task_delegate,
            max_concurrent_tasks=min(self.max_concurrent_tasks, other.max_concurrent_tasks),
            task_timeout_seconds=min(self.task_timeout_seconds, other.task_timeout_seconds),
            model_delta_share=self.model_delta_share and other.model_delta_share,
        )


# ==========================================================================
# Bonds
# ==========================================================================

@dataclass
class Bond:
    """A bilateral trust agreement between two agents.

    Bonds grant elevated collaboration permissions and are time-limited,
    revocable by either party.

    Attributes:
        agent_a: DID of the first agent.
        agent_b: DID of the second agent.
        permissions: The agreed-upon permission scope.
        bond_id: Unique bond identifier.
        established_at: When the bond was established.
        expires_at: When the bond expires.
        renewal: Renewal mode (``"auto"``, ``"manual"``, ``"none"``).
        revoked: Whether the bond has been revoked.
        revoked_by: DID of the revoking agent, if applicable.
    """

    agent_a: str
    agent_b: str
    permissions: BondPermissions = field(default_factory=BondPermissions)
    bond_id: str = field(default_factory=lambda: generate_uuid_short("bond-"))
    established_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    renewal: str = "manual"
    revoked: bool = False
    revoked_by: str | None = None

    def __post_init__(self) -> None:
        if self.expires_at is None:
            self.expires_at = self.established_at + timedelta(days=180)

        duration = (self.expires_at - self.established_at).total_seconds()
        if duration > MAX_BOND_DURATION_SECONDS:
            raise ValueError(
                f"Bond duration ({duration}s) exceeds maximum "
                f"({MAX_BOND_DURATION_SECONDS}s / 365 days)"
            )
        if duration <= 0:
            raise ValueError("Bond expires_at must be after established_at")

        if self.renewal not in ("auto", "manual", "none"):
            raise ValueError(f"Invalid renewal mode: {self.renewal}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a bond record dict."""
        return {
            "bond_id": self.bond_id,
            "agents": [self.agent_a, self.agent_b],
            "permissions": self.permissions.to_dict(),
            "established_at": self.established_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": self.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.expires_at else "",
            "renewal": self.renewal,
            "signatures": {},
        }

    @property
    def is_expired(self) -> bool:
        """Check if this bond has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_active(self) -> bool:
        """Check if this bond is currently active (not expired, not revoked)."""
        return not self.is_expired and not self.revoked

    def permits_knowledge_share(self, knowledge_type: str) -> bool:
        """Check if this bond allows sharing a given knowledge type.

        Args:
            knowledge_type: ``"embedding"``, ``"insight"``, or ``"model_delta"``.

        Returns:
            ``True`` if permitted.
        """
        if not self.is_active:
            return False
        if not self.permissions.knowledge_share:
            return False
        return knowledge_type in self.permissions.knowledge_allowed_types

    def permits_task_delegation(self) -> bool:
        """Check if this bond allows task delegation."""
        return self.is_active and self.permissions.task_delegate

    def permits_model_delta(self) -> bool:
        """Check if this bond allows model delta sharing."""
        return self.is_active and self.permissions.model_delta_share

    def revoke(self, revoked_by: str) -> None:
        """Revoke this bond.

        Args:
            revoked_by: DID of the agent revoking the bond.
        """
        self.revoked = True
        self.revoked_by = revoked_by

    def involves(self, agent_id: str) -> bool:
        """Check if a given agent is party to this bond."""
        return agent_id in (self.agent_a, self.agent_b)

    def peer_of(self, agent_id: str) -> str:
        """Get the DID of the other agent in the bond.

        Args:
            agent_id: One party's DID.

        Returns:
            The other party's DID.

        Raises:
            ValueError: If *agent_id* is not party to this bond.
        """
        if agent_id == self.agent_a:
            return self.agent_b
        if agent_id == self.agent_b:
            return self.agent_a
        raise ValueError(f"{agent_id} is not party to bond {self.bond_id}")


# ==========================================================================
# Trust score
# ==========================================================================

@dataclass
class TrustScoreWeights:
    """Configurable weights for trust score computation.

    Weights MUST sum to 1.0.

    Attributes:
        identity_verification: Weight for DID verification status.
        vouch_count: Weight for number of received vouches.
        bond_count: Weight for number of active bonds.
        interaction_reputation: Weight for peer interaction ratings.
        uptime_ratio: Weight for availability ratio.
    """

    identity_verification: float = 0.20
    vouch_count: float = 0.25
    bond_count: float = 0.25
    interaction_reputation: float = 0.20
    uptime_ratio: float = 0.10

    def __post_init__(self) -> None:
        total = (
            self.identity_verification
            + self.vouch_count
            + self.bond_count
            + self.interaction_reputation
            + self.uptime_ratio
        )
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Trust score weights must sum to 1.0, got {total:.4f}")


def compute_trust_score(
    is_verified: bool,
    vouch_count: int,
    bond_count: int,
    interaction_reputation: float,
    uptime_ratio: float,
    weights: TrustScoreWeights | None = None,
) -> float:
    """Compute an agent's trust score per OCP §4.2.2.

    The score is a weighted sum in the range [0.0, 1.0]:

    .. code-block:: text

        trust_score = w1 * identity_verification
                    + w2 * min(vouch_count / 10, 1.0)
                    + w3 * min(bond_count / 5, 1.0)
                    + w4 * interaction_reputation
                    + w5 * uptime_ratio

    Args:
        is_verified: Whether the agent's DID is verified.
        vouch_count: Number of valid vouches received.
        bond_count: Number of active bonds.
        interaction_reputation: Rolling average of peer ratings (0.0–1.0).
        uptime_ratio: Online time / total time since registration (0.0–1.0).
        weights: Custom weight configuration. Uses defaults if ``None``.

    Returns:
        Trust score in [0.0, 1.0], rounded to 4 decimal places.
    """
    w = weights or TrustScoreWeights()
    score = (
        w.identity_verification * (1.0 if is_verified else 0.0)
        + w.vouch_count * min(vouch_count / 10.0, 1.0)
        + w.bond_count * min(bond_count / 5.0, 1.0)
        + w.interaction_reputation * max(0.0, min(interaction_reputation, 1.0))
        + w.uptime_ratio * max(0.0, min(uptime_ratio, 1.0))
    )
    return round(max(0.0, min(score, 1.0)), 4)


def determine_trust_level(
    is_verified: bool,
    vouch_count: int,
    bond_count: int,
    is_certified: bool = False,
) -> TrustLevel:
    """Determine an agent's trust level from its current state.

    Args:
        is_verified: Whether the DID is verified.
        vouch_count: Number of valid vouches from Level 2+ agents.
        bond_count: Number of active bonds.
        is_certified: Whether OCP Foundation has certified the agent.

    Returns:
        The appropriate :class:`TrustLevel`.
    """
    if is_certified:
        return TrustLevel.CERTIFIED
    if bond_count >= 1 and vouch_count >= 3:
        return TrustLevel.BONDED
    if vouch_count >= 3:
        return TrustLevel.VOUCHED
    if is_verified:
        return TrustLevel.IDENTIFIED
    return TrustLevel.ANONYMOUS
