"""Tests for OCPUMF message building, signing, and validation.

Compliance category: Message Building & Validation (8 tests)
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from ocp.messages import (
    MessageBuilder,
    MessageType,
    MessageValidator,
    Priority,
    build_ack,
    build_error,
    is_expired,
)
from ocp.exceptions import OCPAuthError, OCPValidationError


class TestMessageBuilder:
    """OCP-SPEC §4.2 — OCPUMF construction."""

    def test_complete_message(self, identity, peer_identity):
        msg = (
            MessageBuilder(identity.agent_id, identity.signing_keys)
            .to(peer_identity.agent_id)
            .type(MessageType.KNOWLEDGE_SHARE)
            .payload({"knowledge_type": "insight"})
            .ttl(7200)
            .tag("oncology", "imaging")
            .language("en")
            .require_ack()
            .priority(Priority.HIGH)
            .correlate("msg-00000000-0000-0000-0000")
            .trace("trace-abc123")
            .build()
        )
        assert msg["ocp_version"] == "1.0"
        assert msg["message_id"].startswith("msg-")
        assert msg["sender"]["agent_id"] == identity.agent_id
        assert msg["sender"]["signature"] != ""
        assert msg["receiver"]["agent_id"] == peer_identity.agent_id
        assert msg["receiver"]["broadcast"] is False
        assert msg["message_type"] == "knowledge_share"
        assert msg["priority"] == "high"
        assert msg["ttl"] == 7200
        assert msg["payload"] == {"knowledge_type": "insight"}
        assert msg["metadata"]["tags"] == ["oncology", "imaging"]
        assert msg["metadata"]["language"] == "en"
        assert msg["metadata"]["requires_ack"] is True
        assert msg["metadata"]["correlation_id"] == "msg-00000000-0000-0000-0000"
        assert msg["metadata"]["trace_id"] == "trace-abc123"

    def test_broadcast_message(self, identity):
        msg = (
            MessageBuilder(identity.agent_id, identity.signing_keys)
            .to_broadcast()
            .type(MessageType.BROADCAST)
            .payload({"announcement": "hello network"})
            .build()
        )
        assert msg["receiver"]["broadcast"] is True
        assert "broadcast" in msg["receiver"]["agent_id"]

    def test_missing_receiver_raises(self, identity):
        builder = (
            MessageBuilder(identity.agent_id, identity.signing_keys)
            .type(MessageType.ACK)
            .payload({})
        )
        with pytest.raises(OCPValidationError, match="Receiver"):
            builder.build()

    def test_ttl_too_low_raises(self, identity):
        with pytest.raises(OCPValidationError):
            MessageBuilder(identity.agent_id, identity.signing_keys).ttl(0)

    def test_ttl_too_high_raises(self, identity):
        with pytest.raises(OCPValidationError):
            MessageBuilder(identity.agent_id, identity.signing_keys).ttl(100_000)

    def test_unique_message_ids(self, identity, peer_identity):
        ids = set()
        for _ in range(100):
            msg = (
                MessageBuilder(identity.agent_id, identity.signing_keys)
                .to(peer_identity.agent_id)
                .type(MessageType.ACK)
                .payload({})
                .build()
            )
            ids.add(msg["message_id"])
        assert len(ids) == 100


class TestMessageValidator:
    """OCP-SPEC §7.2 — Message validation and signature verification."""

    def test_valid_message_passes(self, identity, peer_identity, sample_message):
        validator = MessageValidator()
        validator.validate(sample_message, identity.signing_keys.public_key_bytes)

    def test_structure_only_validation(self, sample_message):
        validator = MessageValidator()
        validator.validate_structure(sample_message)

    def test_missing_field_rejected(self):
        validator = MessageValidator()
        with pytest.raises(OCPValidationError, match="Missing required field"):
            validator.validate_structure({"ocp_version": "1.0"})

    def test_wrong_version_rejected(self, sample_message):
        sample_message["ocp_version"] = "99.0"
        validator = MessageValidator()
        with pytest.raises(OCPValidationError, match="Unsupported"):
            validator.validate_structure(sample_message)

    def test_invalid_message_type_rejected(self, sample_message):
        sample_message["message_type"] = "invented_type"
        validator = MessageValidator()
        with pytest.raises(OCPValidationError, match="Unknown"):
            validator.validate_structure(sample_message)

    def test_wrong_key_signature_rejected(self, sample_message):
        wrong_keys = SigningKeyPair.generate()
        validator = MessageValidator()
        with pytest.raises(OCPAuthError):
            validator.validate_signature(sample_message, wrong_keys.public_key_bytes)

    def test_tampered_payload_signature_rejected(self, identity, sample_message):
        sample_message["payload"]["tampered"] = True
        validator = MessageValidator()
        with pytest.raises(OCPAuthError):
            validator.validate_signature(sample_message, identity.signing_keys.public_key_bytes)


class TestMessageExpiry:
    """OCP-SPEC §3.4 — TTL enforcement."""

    def test_fresh_message_not_expired(self, sample_message):
        assert not is_expired(sample_message)

    def test_old_message_expired(self, sample_message):
        old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        sample_message["timestamp"] = old_time
        sample_message["ttl"] = 60
        assert is_expired(sample_message)


class TestHelperBuilders:
    """Convenience message builders."""

    def test_build_ack(self, identity, sample_message):
        ack = build_ack(sample_message, identity.agent_id, identity.signing_keys)
        assert ack["message_type"] == "ack"
        assert ack["payload"]["acknowledged_message_id"] == sample_message["message_id"]
        assert ack["metadata"]["correlation_id"] == sample_message["message_id"]

    def test_build_error(self, identity, peer_identity):
        err = build_error(
            "OCP-400", "Bad request", "msg-ref-id",
            identity.agent_id, identity.signing_keys, peer_identity.agent_id,
            details={"field": "payload"},
        )
        assert err["message_type"] == "error"
        assert err["payload"]["error_code"] == "OCP-400"
        assert err["payload"]["reference_message_id"] == "msg-ref-id"
        assert err["payload"]["details"]["field"] == "payload"
