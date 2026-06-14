"""
OCPUMF Ethics Metadata Builder and Validator.
Ref: Integration Spec INT-001, INT-002, INT-003, INT-004

Builds and validates the metadata.ethics object for OCP messages.
"""
from __future__ import annotations
from typing import Any
from ocp.ethics.constants import RiskTier, EVLCode


# All valid message types including ethics additions
ETHICS_MESSAGE_TYPES = frozenset([
    "ethics_report", "ethics_appeal", "pur_update",
    "decommission_notice", "sanctions_screen", "cascade_alert",
])

# All valid EVL error codes
EVL_ERROR_CODES = frozenset([c.value for c in EVLCode])


class EthicsMetadataBuilder:
    """
    Builds the metadata.ethics object for OCPUMF messages.

    Usage:
        builder = EthicsMetadataBuilder()
        ethics = builder.build(
            risk_tier="high",
            consent_tokens=[token.to_dict()],
            bias_disclosure=disclosure.to_dict(),
        )
        message["metadata"]["ethics"] = ethics
    """

    def build(self, risk_tier: str = None,
              consent_tokens: list[dict] = None,
              bias_disclosure: dict = None,
              human_approval: dict = None,
              compute_footprint: dict = None,
              synthetic_content: dict = None,
              dual_use_assessment: str = None,
              psychological_profile_consent: dict = None,
              cognitive_data_classification: bool = None,
              evl_result: dict = None) -> dict:
        """Build a complete metadata.ethics object."""
        ethics = {}

        if risk_tier:
            ethics["risk_tier"] = risk_tier
        if consent_tokens:
            ethics["consent_tokens"] = consent_tokens
        if bias_disclosure:
            ethics["bias_disclosure"] = bias_disclosure
        if human_approval:
            ethics["human_approval"] = human_approval
        if compute_footprint:
            ethics["compute_footprint"] = compute_footprint
        if synthetic_content:
            ethics["synthetic_content"] = synthetic_content
        if dual_use_assessment:
            ethics["dual_use_assessment"] = dual_use_assessment
        if psychological_profile_consent is not None:
            ethics["psychological_profile_consent"] = psychological_profile_consent
        if cognitive_data_classification is not None:
            ethics["cognitive_data_classification"] = cognitive_data_classification
        if evl_result:
            ethics["evl_result"] = evl_result

        return ethics

    def build_human_approval(self, approver_id: str, method: str,
                             scope: str, signature: str,
                             approved_at: str = None) -> dict:
        """Build a human_approval record."""
        from datetime import datetime, timezone
        return {
            "approver_id": approver_id,
            "approved_at": approved_at or datetime.now(timezone.utc).isoformat(),
            "method": method,
            "scope": scope,
            "signature": signature,
        }

    def build_compute_footprint(self, flops: float = None, energy_kwh: float = None,
                                 carbon_gco2e: float = None, region: str = None) -> dict:
        """Build a compute_footprint record."""
        fp = {}
        if flops is not None: fp["flops_estimated"] = flops
        if energy_kwh is not None: fp["energy_kwh"] = energy_kwh
        if carbon_gco2e is not None: fp["carbon_gco2e"] = carbon_gco2e
        if region: fp["datacenter_region"] = region
        return fp


class EthicsMetadataValidator:
    """Validates metadata.ethics objects against the schema."""

    REQUIRED_FIELDS_ETHICAL = {"risk_tier", "evl_result"}

    def validate(self, ethics: dict, conformance_level: str = "ocp_core") -> tuple[bool, list[str]]:
        """Validate ethics metadata. Returns (is_valid, issues)."""
        issues = []

        if conformance_level == "ocp_ethical":
            for field in self.REQUIRED_FIELDS_ETHICAL:
                if field not in ethics:
                    issues.append(f"Missing required field for OCP Ethical: {field}")

        # Validate risk_tier
        if "risk_tier" in ethics:
            valid_tiers = {t.value for t in RiskTier}
            if ethics["risk_tier"] not in valid_tiers:
                issues.append(f"Invalid risk_tier: {ethics['risk_tier']}")

        # Validate consent tokens
        for token in ethics.get("consent_tokens", []):
            if not token.get("token_id"):
                issues.append("Consent token missing token_id")
            if not token.get("signature"):
                issues.append("Consent token missing signature")
            if not token.get("scope"):
                issues.append("Consent token missing scope")

        # Validate human_approval
        ha = ethics.get("human_approval")
        if ha:
            required = {"approver_id", "approved_at", "method", "signature"}
            missing = required - ha.keys()
            if missing:
                issues.append(f"human_approval missing fields: {missing}")

        # Validate synthetic_content
        sc = ethics.get("synthetic_content")
        if sc:
            required = {"is_synthetic", "generation_method", "generating_agent", "generated_at"}
            missing = required - sc.keys()
            if missing:
                issues.append(f"synthetic_content missing fields: {missing}")

        # Validate dual_use_assessment
        dua = ethics.get("dual_use_assessment")
        if dua and dua not in ("no_dual_use_concern", "dual_use_aware", "dual_use_restricted"):
            issues.append(f"Invalid dual_use_assessment: {dua}")

        return len(issues) == 0, issues
