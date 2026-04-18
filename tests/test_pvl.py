"""Tests for the Privacy Validation Layer.

Compliance category: Privacy Validation Layer (10 tests)
"""

import json

import pytest

from ocp.pvl import validate_knowledge_payload, enforce_pvl, PVLResult
from ocp.exceptions import OCPPrivacyViolation


class TestPVL001_PII:
    """PVL-001: PII detection in knowledge payloads."""

    def test_ssn_detected(self, sample_insight_payload):
        sample_insight_payload["payload"]["description"] = "SSN is 123-45-6789"
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-001"
        assert "SSN" in result.rejection_reason

    def test_email_detected(self, sample_insight_payload):
        sample_insight_payload["payload"]["description"] = "Contact john.doe@example.com for details"
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-001"
        assert "email" in result.rejection_reason

    def test_phone_detected(self, sample_insight_payload):
        sample_insight_payload["payload"]["description"] = "Call 555-123-4567 for info"
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-001"

    def test_credit_card_detected(self, sample_insight_payload):
        sample_insight_payload["payload"]["description"] = "Card 4111 1111 1111 1111"
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-001"

    def test_ip_address_detected(self, sample_insight_payload):
        sample_insight_payload["payload"]["description"] = "Server at 192.168.1.100"
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-001"

    def test_deeply_nested_pii_detected(self, sample_insight_payload):
        sample_insight_payload["payload"]["features"] = [
            {"name": "agent_email@company.com", "type": "string"}
        ]
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-001"

    def test_clean_payload_passes(self, sample_insight_payload):
        result = validate_knowledge_payload(sample_insight_payload)
        assert result.passed
        assert result.rejection_code is None


class TestPVL002_Anonymization:
    """PVL-002: Anonymization enforcement on insights."""

    def test_non_anonymized_rejected(self, sample_insight_payload):
        sample_insight_payload["anonymized"] = False
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-002"

    def test_missing_anonymized_rejected(self, sample_insight_payload):
        del sample_insight_payload["anonymized"]
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-002"


class TestPVL003_DifferentialPrivacy:
    """PVL-003: Differential privacy requirements on model deltas."""

    def test_high_epsilon_rejected(self, sample_model_delta_payload):
        sample_model_delta_payload["differential_privacy"]["epsilon"] = 15.0
        result = validate_knowledge_payload(sample_model_delta_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-003"
        assert "10" in result.rejection_reason

    def test_missing_dp_rejected(self, sample_model_delta_payload):
        del sample_model_delta_payload["differential_privacy"]
        result = validate_knowledge_payload(sample_model_delta_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-003"

    def test_missing_mechanism_rejected(self, sample_model_delta_payload):
        del sample_model_delta_payload["differential_privacy"]["mechanism"]
        result = validate_knowledge_payload(sample_model_delta_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-003"

    def test_valid_dp_passes(self, sample_model_delta_payload):
        result = validate_knowledge_payload(sample_model_delta_payload)
        assert result.passed


class TestPVL004_Provenance:
    """PVL-004: Provenance requirements."""

    def test_missing_provenance_rejected(self, sample_insight_payload):
        del sample_insight_payload["provenance"]
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-004"

    def test_missing_source_agent_rejected(self, sample_insight_payload):
        sample_insight_payload["provenance"] = {"timestamp": "2026-04-03T12:00:00Z"}
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-004"

    def test_missing_timestamp_rejected(self, sample_insight_payload):
        sample_insight_payload["provenance"] = {"source_agent": "did:ocp:testnet:agent-aabbccddeeff"}
        result = validate_knowledge_payload(sample_insight_payload)
        assert not result.passed
        assert result.rejection_code == "PVL-004"


class TestPVL005_Size:
    """PVL-005: Payload size limits."""

    def test_oversized_rejected(self, sample_insight_payload):
        result = validate_knowledge_payload(sample_insight_payload, max_payload_bytes=10)
        assert not result.passed
        assert result.rejection_code == "PVL-005"

    def test_within_limit_passes(self, sample_insight_payload):
        result = validate_knowledge_payload(sample_insight_payload, max_payload_bytes=100_000)
        assert result.passed


class TestPVLCheckOrder:
    """Verify that PVL checks execute in the correct order (§5.2 of spec)."""

    def test_size_checked_before_pii(self, sample_insight_payload):
        sample_insight_payload["payload"]["description"] = "john@example.com"
        result = validate_knowledge_payload(sample_insight_payload, max_payload_bytes=10)
        assert result.rejection_code == "PVL-005"  # size first, not PII

    def test_provenance_checked_before_pii(self, sample_insight_payload):
        del sample_insight_payload["provenance"]
        sample_insight_payload["payload"]["description"] = "john@example.com"
        result = validate_knowledge_payload(sample_insight_payload)
        assert result.rejection_code == "PVL-004"  # provenance before PII


class TestEnforcePVL:
    """Test the enforce_pvl convenience function."""

    def test_raises_on_violation(self, sample_insight_payload):
        sample_insight_payload["anonymized"] = False
        with pytest.raises(OCPPrivacyViolation) as exc_info:
            enforce_pvl(sample_insight_payload)
        assert exc_info.value.pvl_code == "PVL-002"

    def test_passes_silently(self, sample_insight_payload):
        enforce_pvl(sample_insight_payload)  # should not raise

    def test_embedding_passes_pvl(self, sample_embedding_payload):
        result = validate_knowledge_payload(sample_embedding_payload)
        assert result.passed
