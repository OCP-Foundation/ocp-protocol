"""
Dual-Use Classification Engine.
Ref: OCP Ethics Bible v2.1 §31
"""
from __future__ import annotations
from ocp.ethics.constants import DualUseLevel, DUAL_USE_DOMAINS


class DualUseClassifier:
    """Classifies knowledge payloads for dual-use potential."""

    def classify(self, domains: list[str], payload: dict = None) -> DualUseLevel:
        """Determine dual-use level based on domains and payload content."""
        is_dual_use_domain = any(
            d in DUAL_USE_DOMAINS or any(d.startswith(dd) for dd in DUAL_USE_DOMAINS)
            for d in domains
        )
        if not is_dual_use_domain:
            return DualUseLevel.NO_CONCERN

        # Check payload for restricted indicators
        if payload:
            restricted_keywords = {
                "weaponization", "synthesis_route", "exploit_code",
                "enrichment", "gain_of_function", "offensive"
            }
            payload_str = str(payload).lower()
            if any(kw in payload_str for kw in restricted_keywords):
                return DualUseLevel.RESTRICTED

        return DualUseLevel.AWARE

    def validate_sharing(self, level: DualUseLevel, peer_credentials: dict) -> tuple[bool, str | None]:
        """Check if sharing is permitted given dual-use level and peer credentials."""
        if level == DualUseLevel.NO_CONCERN:
            return True, None
        if level == DualUseLevel.AWARE:
            return True, None  # Sharing permitted with acknowledgment
        if level == DualUseLevel.RESTRICTED:
            if peer_credentials.get("verified_research_org"):
                return True, None
            return False, "dual_use_restricted: peer lacks verified research credentials"
        return True, None
