"""
OCP Ethical Conformance Checker.
Ref: Integration Spec INT-032, Ethics Bible §13 (Conformance)

Validates that a node meets OCP Ethical requirements.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ComplianceResult:
    level: str  # "ocp_core", "ocp_knowledge", "ocp_full", "ocp_ethical"
    passed: bool
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        total = len(self.checks_passed) + len(self.checks_failed)
        return len(self.checks_passed) / total if total > 0 else 0.0


class EthicalComplianceChecker:
    """
    Checks whether a node meets OCP Ethical conformance requirements.

    Usage:
        checker = EthicalComplianceChecker()
        result = checker.check(node_config, agent_record, did_document)
    """

    def check(self, config: dict, agent_record: dict = None,
              did_document: dict = None) -> ComplianceResult:
        """Run all OCP Ethical compliance checks."""
        passed = []
        failed = []

        # Ethics module enabled
        if config.get("ethics", {}).get("enabled"):
            passed.append("ethics_module_enabled")
        else:
            failed.append("ethics_module_enabled")

        # EVL enabled
        if config.get("ethics", {}).get("evl", {}).get("enabled"):
            passed.append("evl_enabled")
        else:
            failed.append("evl_enabled")

        # EAL configured
        eal = config.get("ethics", {}).get("eal", {})
        if eal.get("storage_backend") and eal.get("database_url"):
            passed.append("eal_configured")
        else:
            failed.append("eal_configured")

        if eal.get("retention_days", 0) >= 365:
            passed.append("eal_retention_365d")
        else:
            failed.append("eal_retention_365d")

        # PUR sync
        pur = config.get("ethics", {}).get("pur", {})
        if pur.get("sync_interval_hours", 99) <= 24:
            passed.append("pur_sync_24h")
        else:
            failed.append("pur_sync_24h")

        # Agent Record checks
        if agent_record:
            if agent_record.get("ethics_contact"):
                passed.append("ethics_contact_present")
            else:
                failed.append("ethics_contact_present")

            if agent_record.get("evl_enabled"):
                passed.append("agent_evl_enabled")
            else:
                failed.append("agent_evl_enabled")

            if agent_record.get("risk_tier"):
                passed.append("risk_tier_classified")
            else:
                failed.append("risk_tier_classified")

            if agent_record.get("transparency_card_url"):
                passed.append("transparency_card_published")
            else:
                failed.append("transparency_card_published")

        # DID Document checks
        if did_document:
            services = did_document.get("service", [])
            types = {s.get("type") for s in services}

            if "OCPEthicsContact" in types:
                passed.append("did_ethics_contact_service")
            else:
                failed.append("did_ethics_contact_service")

            if "OCPTransparencyCard" in types:
                passed.append("did_transparency_card_service")
            else:
                failed.append("did_transparency_card_service")

        all_passed = len(failed) == 0
        return ComplianceResult(
            level="ocp_ethical",
            passed=all_passed,
            checks_passed=passed,
            checks_failed=failed
        )
