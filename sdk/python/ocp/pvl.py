"""Privacy Validation Layer (PVL).

The PVL is a mandatory gatekeeper that validates every knowledge payload
before transmission over OCP. It enforces:

- PVL-001: No personally identifiable information (PII) in payloads
- PVL-002: All insights must be marked as anonymized
- PVL-003: Model deltas must meet differential privacy requirements
- PVL-004: All knowledge must include provenance information
- PVL-005: Payload size limits
- PVL-006: Knowledge type must be permitted by bond (checked externally)

.. warning::
    The PII scanner in this reference implementation uses regex patterns.
    Production deployments should augment this with a dedicated NER model
    for more comprehensive PII detection.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ocp.constants import MAX_EPSILON, MAX_PAYLOAD_SIZE
from ocp.exceptions import OCPPrivacyViolation


# ---- PII patterns (reference implementation) ----
# Production should use a trained NER model for comprehensive detection.

_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "email"),
    (re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"), "phone"),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "credit_card"),
    (re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ), "ip_address"),
    (re.compile(
        r"\b[A-Z]{1,2}\d{1,2}\s?\d[A-Z]{2}\b", re.IGNORECASE
    ), "uk_postcode"),
    (re.compile(r"\b\d{3}-\d{4}-\d{4}\b"), "jp_phone"),
]


@dataclass(frozen=True)
class PVLResult:
    """Result of a Privacy Validation Layer check.

    Attributes:
        passed: ``True`` if the payload passed all checks.
        rejection_code: PVL code if rejected (e.g., ``"PVL-001"``).
        rejection_reason: Human-readable explanation if rejected.
    """

    passed: bool
    rejection_code: str | None = None
    rejection_reason: str | None = None


def _scan_for_pii(text: str) -> list[tuple[str, str]]:
    """Scan text for PII patterns.

    Args:
        text: Text to scan.

    Returns:
        List of ``(matched_text, pii_type)`` tuples.
    """
    findings: list[tuple[str, str]] = []
    for pattern, pii_type in _PII_PATTERNS:
        for match in pattern.finditer(text):
            findings.append((match.group(), pii_type))
    return findings


def _deep_extract_strings(obj: Any, depth: int = 0, max_depth: int = 20) -> str:
    """Recursively extract all string values from a nested structure.

    Args:
        obj: Any JSON-compatible object.
        depth: Current recursion depth.
        max_depth: Maximum recursion depth to prevent stack overflow.

    Returns:
        All string values concatenated with spaces.
    """
    if depth > max_depth:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_deep_extract_strings(v, depth + 1, max_depth) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_deep_extract_strings(item, depth + 1, max_depth) for item in obj)
    return ""


def validate_knowledge_payload(
    payload: dict[str, Any],
    max_payload_bytes: int = MAX_PAYLOAD_SIZE,
) -> PVLResult:
    """Run all PVL checks on a knowledge payload.

    Checks are executed in order of severity:
    PVL-005 (size) → PVL-004 (provenance) → PVL-002 (anonymization)
    → PVL-003 (differential privacy) → PVL-001 (PII scan).

    Args:
        payload: Knowledge payload dict.
        max_payload_bytes: Maximum allowed payload size.

    Returns:
        A :class:`PVLResult` indicating pass or fail.
    """
    # PVL-005: Size check
    payload_bytes = len(json.dumps(payload).encode("utf-8"))
    if payload_bytes > max_payload_bytes:
        return PVLResult(
            passed=False,
            rejection_code="PVL-005",
            rejection_reason=(
                f"Payload size ({payload_bytes:,} bytes) exceeds limit "
                f"({max_payload_bytes:,} bytes)"
            ),
        )

    knowledge_type = payload.get("knowledge_type")

    # PVL-004: Provenance check (required for insights and model deltas)
    if knowledge_type in ("insight", "model_delta"):
        prov = payload.get("provenance")
        if not prov or not prov.get("source_agent") or not prov.get("timestamp"):
            return PVLResult(
                passed=False,
                rejection_code="PVL-004",
                rejection_reason="Missing or incomplete provenance information",
            )

    # PVL-002: Anonymization check (required for insights)
    if knowledge_type == "insight" and not payload.get("anonymized", False):
        return PVLResult(
            passed=False,
            rejection_code="PVL-002",
            rejection_reason=(
                "Insight payload must have anonymized=true. "
                "OCP prohibits sharing non-anonymized knowledge."
            ),
        )

    # PVL-003: Differential privacy check (required for model deltas)
    if knowledge_type == "model_delta":
        dp = payload.get("differential_privacy", {})
        if not dp:
            return PVLResult(
                passed=False,
                rejection_code="PVL-003",
                rejection_reason="Model delta missing differential_privacy parameters",
            )
        eps = dp.get("epsilon", float("inf"))
        if eps > MAX_EPSILON:
            return PVLResult(
                passed=False,
                rejection_code="PVL-003",
                rejection_reason=(
                    f"Epsilon ({eps}) exceeds maximum ({MAX_EPSILON}). "
                    "Increase noise or reduce privacy budget."
                ),
            )
        if "delta" not in dp:
            return PVLResult(
                passed=False,
                rejection_code="PVL-003",
                rejection_reason="Missing differential_privacy.delta parameter",
            )
        if "mechanism" not in dp:
            return PVLResult(
                passed=False,
                rejection_code="PVL-003",
                rejection_reason="Missing differential_privacy.mechanism parameter",
            )

    # PVL-001: PII scan (all knowledge types)
    all_text = _deep_extract_strings(payload)
    pii_findings = _scan_for_pii(all_text)
    if pii_findings:
        types_found = sorted({t for _, t in pii_findings})
        return PVLResult(
            passed=False,
            rejection_code="PVL-001",
            rejection_reason=f"PII detected in payload: {', '.join(types_found)}",
        )

    return PVLResult(passed=True)


def enforce_pvl(
    payload: dict[str, Any],
    max_payload_bytes: int = MAX_PAYLOAD_SIZE,
) -> None:
    """Validate a payload and raise on failure.

    Convenience wrapper around :func:`validate_knowledge_payload` that
    raises :class:`OCPPrivacyViolation` instead of returning a result.

    Args:
        payload: Knowledge payload dict.
        max_payload_bytes: Maximum allowed payload size.

    Raises:
        OCPPrivacyViolation: If any PVL check fails.
    """
    result = validate_knowledge_payload(payload, max_payload_bytes)
    if not result.passed:
        raise OCPPrivacyViolation(
            message=result.rejection_reason or "PVL validation failed",
            pvl_code=result.rejection_code or "PVL-000",
        )
