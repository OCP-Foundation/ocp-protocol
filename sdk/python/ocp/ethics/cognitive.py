"""
Cognitive Data Protection Layer.
Ref: OCP Ethics Bible v2.1 §34
"""
from __future__ import annotations
from ocp.ethics.constants import COGNITIVE_DATA_EPSILON, RiskTier


class CognitiveDataProtector:
    """
    Protects cognitive data (BCI, neural recordings, mental state inference).
    Auto-elevates to High risk. Enforces epsilon <= 1.0.
    """

    COGNITIVE_INDICATORS = frozenset([
        "bci", "neural", "eeg", "fmri", "cognitive_assessment",
        "mental_state", "brain_computer_interface", "eye_tracking",
        "emotion_detection", "thought_inference",
    ])

    def is_cognitive_data(self, payload: dict) -> bool:
        """Detect if payload contains cognitive data."""
        payload_str = str(payload).lower()
        return any(ind in payload_str for ind in self.COGNITIVE_INDICATORS)

    def validate(self, payload: dict, ethics: dict) -> tuple[bool, str | None]:
        """Validate cognitive data protections are in place."""
        if not self.is_cognitive_data(payload):
            return True, None

        # Check consent
        consent_tokens = ethics.get("consent_tokens", [])
        has_cognitive_consent = any(
            t.get("basis") == "explicit_cognitive_consent"
            for t in consent_tokens
        )
        if not has_cognitive_consent:
            return False, "Cognitive data requires explicit_cognitive_consent token"

        # Check epsilon
        dp = payload.get("differential_privacy", {})
        epsilon = dp.get("epsilon", float("inf"))
        if epsilon > COGNITIVE_DATA_EPSILON:
            return False, f"Cognitive data epsilon must be <= {COGNITIVE_DATA_EPSILON}, got {epsilon}"

        # Reject raw neural data
        if payload.get("contains_raw_neural", False):
            return False, "Raw neural data must not be shared over OCP"

        return True, None

    def auto_classify_risk(self, payload: dict) -> RiskTier | None:
        """If cognitive data detected, force High risk."""
        if self.is_cognitive_data(payload):
            return RiskTier.HIGH
        return None
