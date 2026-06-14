"""
Ethics Validation Layer (EVL) — 6-step enforcement pipeline.
Ref: OCP Ethics Bible v2.1 §35

Runs in series after PVL:
  Outbound: Application → PVL → EVL → Transport
  Inbound:  Transport → PVL → EVL → Application

Steps:
  1. Prohibited use scan (PUR pattern matching)
  2. Consent token validation (regulated domains)
  3. Autonomy gate (HITL for physical actuators)
  4. Bias disclosure check (advisory for high-risk)
  5. Synthetic content label check
  6. Cascade circuit breaker
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any
from ocp.ethics.constants import (
    EVLCode, RiskTier, REGULATED_DOMAINS, PHYSICAL_ACTUATOR_DOMAINS
)
from ocp.ethics.exceptions import EVLRejection


@dataclass
class EVLResult:
    """Result of EVL validation."""
    status: str  # "PASS" or "REJECT"
    checks_performed: list[str] = field(default_factory=list)
    code: EVLCode | None = None
    reason: str | None = None
    remediation: str | None = None
    warnings: list[str] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            from datetime import datetime, timezone
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        d = {
            "status": self.status,
            "checks_performed": self.checks_performed,
            "timestamp": self.timestamp,
        }
        if self.code:
            d["code"] = self.code.value
        if self.reason:
            d["reason"] = self.reason
        if self.remediation:
            d["remediation"] = self.remediation
        if self.warnings:
            d["warnings"] = self.warnings
        return d


@dataclass
class EVLCheck:
    """Individual check result within the EVL pipeline."""
    name: str
    passed: bool
    code: EVLCode | None = None
    reason: str | None = None
    remediation: str | None = None
    is_warning: bool = False


class EVL:
    """
    Ethics Validation Layer — 6-step pipeline.

    Usage:
        evl = EVL(pur=pur, eal=eal, consent_mgr=consent_mgr,
                  cascade_breaker=cascade, risk_classifier=risk_cls)
        result = await evl.validate(message)
    """

    def __init__(self, pur=None, eal=None, consent_mgr=None,
                 cascade_breaker=None, risk_classifier=None,
                 bias_validator=None, synthetic_labeler=None,
                 strict_bias: bool = False):
        self.pur = pur
        self.eal = eal
        self.consent_mgr = consent_mgr
        self.cascade_breaker = cascade_breaker
        self.risk_classifier = risk_classifier
        self.bias_validator = bias_validator
        self.synthetic_labeler = synthetic_labeler
        self.strict_bias = strict_bias  # reject vs warn on missing bias_disclosure

    async def validate(self, message: dict) -> EVLResult:
        """
        Run the full 6-step EVL pipeline on a message.
        Returns EVLResult. On rejection, also logs to EAL.
        """
        checks_performed = []
        warnings = []
        metadata = message.get("metadata", {})
        ethics = metadata.get("ethics", {})
        payload = message.get("payload", {})
        msg_type = message.get("message_type", "")
        msg_id = message.get("message_id", "")
        sender = message.get("sender", {}).get("agent_id", "")
        receiver = message.get("receiver", {}).get("agent_id", "")
        tags = metadata.get("tags", [])

        # Determine risk tier
        risk_tier = ethics.get("risk_tier", RiskTier.LIMITED.value)

        # Step 1: Prohibited use scan
        checks_performed.append("prohibited_use_scan")
        if self.pur:
            check = await self._step1_prohibited_use(message, tags)
            if not check.passed:
                result = EVLResult(
                    status="REJECT", checks_performed=checks_performed,
                    code=check.code, reason=check.reason,
                    remediation=check.remediation
                )
                await self._log_to_eal(message, result)
                return result

        # Step 2: Consent token validation
        checks_performed.append("consent_verification")
        if self.consent_mgr:
            check = await self._step2_consent(message, tags, ethics)
            if not check.passed:
                result = EVLResult(
                    status="REJECT", checks_performed=checks_performed,
                    code=check.code, reason=check.reason,
                    remediation=check.remediation
                )
                await self._log_to_eal(message, result)
                return result

        # Step 3: Autonomy gate
        checks_performed.append("autonomy_gate")
        check = await self._step3_autonomy(message, ethics)
        if not check.passed:
            result = EVLResult(
                status="REJECT", checks_performed=checks_performed,
                code=check.code, reason=check.reason,
                remediation=check.remediation
            )
            await self._log_to_eal(message, result)
            return result

        # Step 4: Bias disclosure check
        checks_performed.append("bias_check")
        check = await self._step4_bias(payload, ethics, risk_tier)
        if not check.passed and not check.is_warning:
            result = EVLResult(
                status="REJECT", checks_performed=checks_performed,
                code=check.code, reason=check.reason,
                remediation=check.remediation
            )
            await self._log_to_eal(message, result)
            return result
        elif check.is_warning and check.reason:
            warnings.append(check.reason)

        # Step 5: Synthetic content label check
        checks_performed.append("synthetic_content_check")
        check = await self._step5_synthetic(payload, ethics)
        if not check.passed:
            result = EVLResult(
                status="REJECT", checks_performed=checks_performed,
                code=check.code, reason=check.reason,
                remediation=check.remediation
            )
            await self._log_to_eal(message, result)
            return result

        # Step 6: Cascade circuit breaker
        checks_performed.append("cascade_check")
        if self.cascade_breaker:
            check = await self._step6_cascade(msg_id)
            if not check.passed:
                result = EVLResult(
                    status="REJECT", checks_performed=checks_performed,
                    code=check.code, reason=check.reason,
                    remediation=check.remediation
                )
                await self._log_to_eal(message, result)
                return result

        # All checks passed
        result = EVLResult(
            status="PASS", checks_performed=checks_performed,
            warnings=warnings
        )
        await self._log_to_eal(message, result)
        return result

    async def _step1_prohibited_use(self, message: dict, tags: list) -> EVLCheck:
        """Step 1: Match against Prohibited Use Registry."""
        match = await self.pur.scan(message)
        if match:
            return EVLCheck(
                name="prohibited_use_scan", passed=False,
                code=match.evl_code, reason=match.description,
                remediation=match.remediation
            )
        return EVLCheck(name="prohibited_use_scan", passed=True)

    async def _step2_consent(self, message: dict, tags: list,
                              ethics: dict) -> EVLCheck:
        """Step 2: Validate consent tokens for regulated domains."""
        domains = set(tags)
        regulated = domains & REGULATED_DOMAINS
        if not regulated:
            return EVLCheck(name="consent_verification", passed=True)

        tokens = ethics.get("consent_tokens", [])
        if not tokens:
            return EVLCheck(
                name="consent_verification", passed=False,
                code=EVLCode.EVL_007,
                reason=f"Missing consent token for regulated domains: {regulated}",
                remediation="Attach valid consent token with matching scope"
            )

        for domain in regulated:
            valid = await self.consent_mgr.validate_for_domain(tokens, domain)
            if not valid:
                return EVLCheck(
                    name="consent_verification", passed=False,
                    code=EVLCode.EVL_007,
                    reason=f"No valid consent token covers domain: {domain}",
                    remediation=f"Attach consent token with scope covering {domain}"
                )

        return EVLCheck(name="consent_verification", passed=True)

    async def _step3_autonomy(self, message: dict, ethics: dict) -> EVLCheck:
        """Step 3: HITL gate for autonomous execution in physical domains."""
        if message.get("message_type") != "task_request":
            return EVLCheck(name="autonomy_gate", passed=True)

        payload = message.get("payload", {})
        constraints = payload.get("constraints", {})
        task_ethics = constraints.get("ethics", {})

        if not task_ethics.get("autonomous_execution", False):
            return EVLCheck(name="autonomy_gate", passed=True)

        required_caps = constraints.get("required_capabilities", [])
        task_domains = set()
        for cap in required_caps:
            parts = cap.split(":")
            if len(parts) >= 2:
                task_domains.add(parts[1])

        needs_hitl = task_domains & PHYSICAL_ACTUATOR_DOMAINS
        if not needs_hitl:
            return EVLCheck(name="autonomy_gate", passed=True)

        human_approval = ethics.get("human_approval")
        if not human_approval:
            return EVLCheck(
                name="autonomy_gate", passed=False,
                code=EVLCode.EVL_008,
                reason=f"Autonomous execution in physical domain {needs_hitl} requires human approval",
                remediation="Add human_approval record with MFA signature"
            )

        # Validate approval has required fields
        required = {"approver_id", "approved_at", "method", "signature"}
        if not required.issubset(human_approval.keys()):
            return EVLCheck(
                name="autonomy_gate", passed=False,
                code=EVLCode.EVL_008,
                reason="human_approval record incomplete",
                remediation=f"Required fields: {required}"
            )

        return EVLCheck(name="autonomy_gate", passed=True)

    async def _step4_bias(self, payload: dict, ethics: dict,
                           risk_tier: str) -> EVLCheck:
        """Step 4: Bias disclosure check (advisory or strict)."""
        knowledge_type = payload.get("knowledge_type")
        if knowledge_type not in ("insight", "embedding", "model_delta"):
            return EVLCheck(name="bias_check", passed=True)

        is_high_risk = risk_tier in (RiskTier.HIGH.value, "high")
        has_disclosure = "bias_disclosure" in ethics and ethics["bias_disclosure"]

        if not has_disclosure and is_high_risk:
            if self.strict_bias:
                return EVLCheck(
                    name="bias_check", passed=False,
                    code=EVLCode.EVL_007,
                    reason="Missing bias_disclosure on high-risk knowledge payload",
                    remediation="Add bias_disclosure with known_biases, mitigation, residual_risk"
                )
            else:
                return EVLCheck(
                    name="bias_check", passed=True, is_warning=True,
                    reason="Advisory: bias_disclosure missing on high-risk payload"
                )

        return EVLCheck(name="bias_check", passed=True)

    async def _step5_synthetic(self, payload: dict, ethics: dict) -> EVLCheck:
        """Step 5: Verify synthetic content labeling."""
        # Check if payload appears to contain generated content
        is_synthetic = payload.get("is_synthetic", False)
        knowledge_type = payload.get("knowledge_type")

        if not is_synthetic and knowledge_type not in ("generated_text", "generated_image",
                                                         "generated_audio", "generated_video"):
            return EVLCheck(name="synthetic_content_check", passed=True)

        synthetic_label = ethics.get("synthetic_content")
        if not synthetic_label:
            return EVLCheck(
                name="synthetic_content_check", passed=False,
                code=EVLCode.EVL_011,
                reason="Synthetic content detected without synthetic_content label",
                remediation="Add synthetic_content metadata with generation_method and generating_agent"
            )

        required = {"is_synthetic", "generation_method", "generating_agent", "generated_at"}
        if not required.issubset(synthetic_label.keys()):
            return EVLCheck(
                name="synthetic_content_check", passed=False,
                code=EVLCode.EVL_011,
                reason=f"Incomplete synthetic_content label, missing: {required - synthetic_label.keys()}",
                remediation="Complete all required fields"
            )

        return EVLCheck(name="synthetic_content_check", passed=True)

    async def _step6_cascade(self, message_id: str) -> EVLCheck:
        """Step 6: Check cascade circuit breaker."""
        is_triggered = await self.cascade_breaker.check(message_id)
        if is_triggered:
            return EVLCheck(
                name="cascade_check", passed=False,
                code=EVLCode.EVL_012,
                reason=f"Cascade circuit breaker triggered for {message_id}",
                remediation="Wait for cascade pause period or originator confirmation"
            )
        return EVLCheck(name="cascade_check", passed=True)

    async def _log_to_eal(self, message: dict, result: EVLResult):
        """Log EVL decision to Ethics Audit Log."""
        if self.eal:
            await self.eal.log(
                message_id=message.get("message_id", ""),
                message_type=message.get("message_type", ""),
                sender=message.get("sender", {}).get("agent_id", ""),
                receiver=message.get("receiver", {}).get("agent_id", ""),
                evl_result=result
            )
