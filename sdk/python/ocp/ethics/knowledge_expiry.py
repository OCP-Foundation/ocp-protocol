"""
Knowledge Expiry (valid_until) Checking.
Ref: Integration Spec INT-038, Ethics Bible §24 DC-002

Handles temporal relevance of knowledge payloads.
"""
from __future__ import annotations
from datetime import datetime, timezone


class KnowledgeExpiryChecker:
    """
    Checks and manages knowledge payload expiry.

    Usage:
        checker = KnowledgeExpiryChecker()
        expired = checker.is_expired(payload)
    """

    def is_expired(self, payload: dict) -> bool:
        """Check if a knowledge payload has expired."""
        valid_until = payload.get("valid_until") or payload.get("provenance", {}).get("valid_until")
        if not valid_until:
            return False  # No expiry = valid indefinitely
        now = datetime.now(timezone.utc).isoformat()
        return now > valid_until

    def should_deprioritize(self, payload: dict, staleness_days: int = 90) -> bool:
        """Check if knowledge is stale (no expiry but old)."""
        ts = payload.get("provenance", {}).get("timestamp")
        if not ts:
            return False
        try:
            created = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - created).days
            return age > staleness_days
        except (ValueError, TypeError):
            return False

    def set_expiry(self, payload: dict, valid_until: str) -> dict:
        """Set valid_until on a payload."""
        payload = dict(payload)
        payload["valid_until"] = valid_until
        return payload
