"""
Prohibited Use Registry (PUR) — Pattern matching for 10 prohibited uses.
Ref: OCP Ethics Bible v2.1 §5, Appendix C

Distributed via Agent Registry gossip. Signed by EAB DID.
Monotonic versioning; downgrades rejected.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any
from ocp.ethics.constants import EVLCode


@dataclass
class PURMatch:
    """Result of a PUR pattern match."""
    pur_id: str
    evl_code: EVLCode
    category: str
    description: str
    remediation: str | None = None
    severity: str = "block"


@dataclass
class ProhibitedUsePattern:
    """A single pattern in the PUR."""
    pur_id: str
    version: int
    category: str
    evl_code: EVLCode
    description: str
    pattern: dict
    severity: str = "block"  # "block" or "warn"
    remediation: str | None = None
    issued_by: str = ""
    signature: str = ""


@dataclass
class PUREntry:
    """Alias for ProhibitedUsePattern for backward compat."""
    pass


class PUR:
    """
    Prohibited Use Registry — pattern matching engine.

    Usage:
        pur = PUR()
        pur.load_defaults()
        match = await pur.scan(message)
    """

    def __init__(self):
        self._patterns: dict[str, ProhibitedUsePattern] = {}
        self._version = 0

    def load_defaults(self):
        """Load the 10 default prohibited use patterns."""
        defaults = [
            ProhibitedUsePattern(
                pur_id="pur-001", version=1, category="identity_inference",
                evl_code=EVLCode.EVL_001,
                description="Identity inference without consent",
                pattern={"type": "cross_correlation", "min_signals": 3, "window_seconds": 60},
                remediation="Remove re-identifiable signals; aggregate to k>50"
            ),
            ProhibitedUsePattern(
                pur_id="pur-002", version=1, category="market_manipulation",
                evl_code=EVLCode.EVL_002,
                description="Coordinated price-directional signals",
                pattern={"type": "coordinated_signal", "domains": ["finance", "trading"],
                         "min_agents": 2, "window_seconds": 5},
                remediation="Ensure signals are independent; add timing jitter > 60s"
            ),
            ProhibitedUsePattern(
                pur_id="pur-003", version=1, category="health_data_violation",
                evl_code=EVLCode.EVL_003,
                description="Healthcare payload without consent token",
                pattern={"type": "domain_without_consent", "domains": ["healthcare"]},
                remediation="Obtain IRB approval; attach valid consent token"
            ),
            ProhibitedUsePattern(
                pur_id="pur-004", version=1, category="anticompetitive",
                evl_code=EVLCode.EVL_004,
                description="Anticompetitive coordination pattern",
                pattern={"type": "parallel_aligned_tasks", "min_agents": 2},
                remediation="Review for anticompetitive coordination; consult legal"
            ),
            ProhibitedUsePattern(
                pur_id="pur-005", version=1, category="weaponized_signal",
                evl_code=EVLCode.EVL_005,
                description="Adversarially crafted signal",
                pattern={"type": "provenance_anomaly", "threshold_sigma": 3.0},
                remediation="Regenerate payload from verified source data"
            ),
            ProhibitedUsePattern(
                pur_id="pur-006", version=1, category="lethal_automation",
                evl_code=EVLCode.EVL_006,
                description="Lethal autonomous decision-making",
                pattern={"type": "lethal_capability_check",
                         "capabilities": ["cap:custom:*:lethal_force"]},
                remediation="This use is absolutely prohibited"
            ),
            ProhibitedUsePattern(
                pur_id="pur-007", version=1, category="mass_surveillance",
                evl_code=EVLCode.EVL_001,
                description="Mass surveillance aggregation",
                pattern={"type": "behavioral_aggregation", "min_identifiers": 100,
                         "window_hours": 24},
                remediation="Do not aggregate behavioral signals at population scale"
            ),
            ProhibitedUsePattern(
                pur_id="pur-008", version=1, category="democratic_manipulation",
                evl_code=EVLCode.EVL_001,
                description="Manipulation of democratic processes",
                pattern={"type": "synthetic_consensus_broadcast", "min_agents": 50,
                         "during_election": True},
                remediation="Do not broadcast synthetic consensus during elections"
            ),
            ProhibitedUsePattern(
                pur_id="pur-009", version=1, category="child_exploitation",
                evl_code=EVLCode.EVL_009,
                description="Exploitation of children or vulnerable groups",
                pattern={"type": "minor_targeting", "requires_parental_consent": True},
                remediation="Implement age-appropriate safeguards; obtain parental consent"
            ),
            ProhibitedUsePattern(
                pur_id="pur-010", version=1, category="social_scoring",
                evl_code=EVLCode.EVL_010,
                description="Social scoring system",
                pattern={"type": "behavioral_scoring", "cross_domain": True,
                         "detrimental_action": True},
                remediation="This use is absolutely prohibited"
            ),
        ]
        for p in defaults:
            self._patterns[p.pur_id] = p
        self._version = 1

    async def scan(self, message: dict) -> PURMatch | None:
        """Scan a message against all PUR patterns. Returns first match or None."""
        tags = message.get("metadata", {}).get("tags", [])
        payload = message.get("payload", {})
        msg_type = message.get("message_type", "")
        capabilities = payload.get("constraints", {}).get("required_capabilities", [])

        for pattern in self._patterns.values():
            p = pattern.pattern
            ptype = p.get("type", "")

            # Domain-based checks
            if ptype == "domain_without_consent":
                required_domains = p.get("domains", [])
                if any(t.startswith(d) for t in tags for d in required_domains):
                    consent_tokens = message.get("metadata", {}).get("ethics", {}).get("consent_tokens", [])
                    if not consent_tokens:
                        return PURMatch(
                            pur_id=pattern.pur_id, evl_code=pattern.evl_code,
                            category=pattern.category, description=pattern.description,
                            remediation=pattern.remediation, severity=pattern.severity
                        )

            # Lethal capability check
            if ptype == "lethal_capability_check":
                blocked = p.get("capabilities", [])
                for cap in capabilities:
                    for b in blocked:
                        if b.replace("*", "") in cap or cap in b:
                            return PURMatch(
                                pur_id=pattern.pur_id, evl_code=pattern.evl_code,
                                category=pattern.category, description=pattern.description,
                                remediation=pattern.remediation, severity=pattern.severity
                            )

        return None

    def update(self, entry: ProhibitedUsePattern) -> bool:
        """Update a PUR entry. Rejects downgrades."""
        existing = self._patterns.get(entry.pur_id)
        if existing and entry.version <= existing.version:
            return False  # Reject downgrade
        self._patterns[entry.pur_id] = entry
        self._version = max(self._version, entry.version)
        return True

    @property
    def version(self) -> int:
        return self._version

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)
