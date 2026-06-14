"""
Agent Record Ethics Field Extensions.
Ref: Integration Spec INT-005,006,036,046

Helpers for adding ethics fields to Agent Records.
"""
from __future__ import annotations
from ocp.ethics.constants import RiskTier


ETHICS_FIELDS = {
    "ethics_contact": str,
    "pur_version": str,
    "evl_enabled": bool,
    "risk_tier": str,
    "transparency_card_url": str,
    "data_sovereignty_constraints": list,
    "sanctions_cleared": bool,
    "export_control_program": bool,
}


class AgentRecordEthicsExtension:
    """
    Extends an Agent Record with ethics fields.

    Usage:
        ext = AgentRecordEthicsExtension()
        record = ext.extend(existing_record,
            ethics_contact="ethics@org.com",
            evl_enabled=True, ...)
    """

    def extend(self, record: dict, **ethics_fields) -> dict:
        """Add ethics fields to an existing Agent Record."""
        record = dict(record)
        for key, value in ethics_fields.items():
            if key in ETHICS_FIELDS:
                record[key] = value
        return record

    def validate(self, record: dict, conformance_level: str = "ocp_core") -> tuple[bool, list[str]]:
        """Validate ethics fields in an Agent Record."""
        issues = []
        if conformance_level != "ocp_ethical":
            return True, []

        if not record.get("ethics_contact"):
            issues.append("ethics_contact is required for OCP Ethical")
        if not record.get("evl_enabled"):
            issues.append("evl_enabled must be true for OCP Ethical")
        if not record.get("risk_tier"):
            issues.append("risk_tier is required for OCP Ethical")
        if not record.get("transparency_card_url"):
            issues.append("transparency_card_url is required for OCP Ethical")

        # Validate risk_tier value
        rt = record.get("risk_tier")
        if rt and rt not in {t.value for t in RiskTier}:
            issues.append(f"Invalid risk_tier: {rt}")

        return len(issues) == 0, issues

    def strip_ethics(self, record: dict) -> dict:
        """Remove all ethics fields (for backward compat with Core agents)."""
        return {k: v for k, v in record.items() if k not in ETHICS_FIELDS}
