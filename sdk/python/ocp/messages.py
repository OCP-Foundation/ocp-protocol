"""OCPUMF message builder, serializer, validator, and parser.

This module provides:

- :class:`MessageType` — enum of all OCP message types
- :class:`Priority` — message priority levels
- :class:`MessageBuilder` — fluent builder for constructing signed messages
- :class:`MessageValidator` — structural and cryptographic message validation
- Helper functions for message parsing and serialization
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

import jsoncanon

from ocp.constants import DEFAULT_TTL, MAX_TTL, OCP_VERSION
from ocp.crypto import (
    SigningKeyPair,
    b64url_decode,
    b64url_encode,
    generate_message_id,
    sha3_256,
    verify_signature,
)
from ocp.exceptions import OCPAuthError, OCPValidationError


class MessageType(StrEnum):
    """All OCP v1.0 message types."""

    DISCOVERY_PING = "discovery_ping"
    CAPABILITY_QUERY = "capability_query"
    CAPABILITY_RESPONSE = "capability_response"
    KNOWLEDGE_SHARE = "knowledge_share"
    KNOWLEDGE_ACK = "knowledge_ack"
    TASK_REQUEST = "task_request"
    TASK_RESPONSE = "task_response"
    BOND_REQUEST = "bond_request"
    BOND_NEGOTIATE = "bond_negotiate"
    BOND_ACCEPT = "bond_accept"
    BOND_CONFIRM = "bond_confirm"
    BOND_REVOKE = "bond_revoke"
    CONSENSUS_INITIATE = "consensus_initiate"
    CONSENSUS_VOTE = "consensus_vote"
    CONSENSUS_RESULT = "consensus_result"
    BROADCAST = "broadcast"
    RECOVERY_REQUEST = "recovery_request"
    RECOVERY_SHARE_RESPONSE = "recovery_share_response"
    SHARE_REVOKE = "share_revoke"
    ACK = "ack"
    ERROR = "error"


class Priority(StrEnum):
    """Message priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


# Set of valid message type strings for fast lookup
_VALID_TYPES: frozenset[str] = frozenset(t.value for t in MessageType)


def _utcnow_iso() -> str:
    """Current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MessageBuilder:
    """Fluent builder for constructing signed OCPUMF messages.

    Usage::

        msg = (
            MessageBuilder(sender_id, signing_keys)
            .to(receiver_id)
            .type(MessageType.KNOWLEDGE_SHARE)
            .payload({"knowledge_type": "insight", ...})
            .ttl(3600)
            .tag("oncology", "imaging")
            .require_ack()
            .build()
        )

    Args:
        sender_id: The sending agent's DID.
        signing_keys: The sender's Ed25519 keypair for signing.
    """

    def __init__(self, sender_id: str, signing_keys: SigningKeyPair) -> None:
        self._sender_id = sender_id
        self._signing_keys = signing_keys
        self._receiver_id: str = ""
        self._broadcast: bool = False
        self._message_type: MessageType = MessageType.ACK
        self._priority: Priority = Priority.NORMAL
        self._ttl: int = DEFAULT_TTL
        self._payload: dict[str, Any] = {}
        self._tags: list[str] = []
        self._language: str = "en"
        self._requires_ack: bool = False
        self._correlation_id: str | None = None
        self._trace_id: str | None = None
        self._encryption: dict[str, Any] | None = None

    # --- Receiver ---

    def to(self, receiver_id: str) -> MessageBuilder:
        """Set the receiver agent ID for a direct message."""
        self._receiver_id = receiver_id
        self._broadcast = False
        return self

    def to_broadcast(self, receiver_id: str = "did:ocp:mainnet:broadcast") -> MessageBuilder:
        """Set the message as a broadcast."""
        self._receiver_id = receiver_id
        self._broadcast = True
        return self

    # --- Message properties ---

    def type(self, message_type: MessageType) -> MessageBuilder:
        """Set the message type."""
        self._message_type = message_type
        return self

    def payload(self, data: dict[str, Any]) -> MessageBuilder:
        """Set the message payload."""
        self._payload = data
        return self

    def priority(self, p: Priority) -> MessageBuilder:
        """Set the priority level."""
        self._priority = p
        return self

    def ttl(self, seconds: int) -> MessageBuilder:
        """Set the time-to-live in seconds.

        Raises:
            OCPValidationError: If *seconds* is outside [1, 86400].
        """
        if not 1 <= seconds <= MAX_TTL:
            raise OCPValidationError(
                f"TTL must be between 1 and {MAX_TTL}, got {seconds}",
                code="OCP-400",
            )
        self._ttl = seconds
        return self

    # --- Metadata ---

    def tag(self, *tags: str) -> MessageBuilder:
        """Add one or more tags to the message metadata."""
        self._tags.extend(tags)
        return self

    def language(self, lang: str) -> MessageBuilder:
        """Set the payload language (ISO 639-1 code)."""
        self._language = lang
        return self

    def require_ack(self) -> MessageBuilder:
        """Mark this message as requiring acknowledgement."""
        self._requires_ack = True
        return self

    def correlate(self, message_id: str) -> MessageBuilder:
        """Set the correlation ID (links to a prior message)."""
        self._correlation_id = message_id
        return self

    def trace(self, trace_id: str) -> MessageBuilder:
        """Set a distributed trace ID."""
        self._trace_id = trace_id
        return self

    # --- Encryption ---

    def encrypt(self, encryption_config: dict[str, Any]) -> MessageBuilder:
        """Attach encryption metadata.

        The caller is responsible for encrypting the payload separately
        (see :func:`ocp.crypto.encrypt_payload`). This method sets the
        ``encryption`` envelope field.
        """
        self._encryption = encryption_config
        return self

    # --- Build ---

    def build(self) -> dict[str, Any]:
        """Build and sign the OCPUMF message.

        Returns:
            A complete, signed OCPUMF message dict.

        Raises:
            OCPValidationError: If required fields are missing.
        """
        if not self._receiver_id:
            raise OCPValidationError("Receiver is required", code="OCP-400")

        msg: dict[str, Any] = {
            "ocp_version": OCP_VERSION,
            "message_id": generate_message_id(),
            "timestamp": _utcnow_iso(),
            "ttl": self._ttl,
            "sender": {
                "agent_id": self._sender_id,
                "signature": "",
            },
            "receiver": {
                "agent_id": self._receiver_id,
                "broadcast": self._broadcast,
            },
            "message_type": self._message_type.value,
            "priority": self._priority.value,
            "payload": self._payload,
            "metadata": {
                "tags": self._tags,
                "language": self._language,
                "requires_ack": self._requires_ack,
            },
        }

        if self._encryption:
            msg["encryption"] = self._encryption
        if self._correlation_id:
            msg["metadata"]["correlation_id"] = self._correlation_id
        if self._trace_id:
            msg["metadata"]["trace_id"] = self._trace_id

        # Sign per OCP §7.2:
        # signature = Ed25519_Sign(sk, SHA3-256(canonical_json(msg without sig)))
        msg_for_signing = json.loads(json.dumps(msg))
        msg_for_signing["sender"]["signature"] = ""
        canonical = jsoncanon.canonicalize(msg_for_signing)
        digest = sha3_256(canonical)
        sig = self._signing_keys.sign(digest)
        msg["sender"]["signature"] = b64url_encode(sig)

        return msg


class MessageValidator:
    """Validates OCPUMF messages for structural correctness and signatures.

    Usage::

        validator = MessageValidator()
        validator.validate_structure(msg)          # structure only
        validator.validate_signature(msg, pub_key) # crypto verification
        validator.validate(msg, pub_key)           # both
    """

    _REQUIRED_FIELDS: tuple[str, ...] = (
        "ocp_version", "message_id", "timestamp",
        "sender", "receiver", "message_type", "payload",
    )

    def validate_structure(self, msg: dict[str, Any]) -> None:
        """Validate message structure without cryptographic checks.

        Raises:
            OCPValidationError: On any structural violation.
        """
        for f in self._REQUIRED_FIELDS:
            if f not in msg:
                raise OCPValidationError(f"Missing required field: {f}", code="OCP-400")

        if msg["ocp_version"] != OCP_VERSION:
            raise OCPValidationError(
                f"Unsupported OCP version: {msg['ocp_version']}", code="OCP-400"
            )

        if not msg["message_id"].startswith("msg-"):
            raise OCPValidationError("Invalid message_id format", code="OCP-400")

        if msg["message_type"] not in _VALID_TYPES:
            raise OCPValidationError(
                f"Unknown message_type: {msg['message_type']}", code="OCP-400"
            )

        sender = msg.get("sender", {})
        if "agent_id" not in sender:
            raise OCPValidationError("Missing sender.agent_id", code="OCP-400")
        if "signature" not in sender:
            raise OCPValidationError("Missing sender.signature", code="OCP-400")

        receiver = msg.get("receiver", {})
        if "agent_id" not in receiver:
            raise OCPValidationError("Missing receiver.agent_id", code="OCP-400")

        ttl = msg.get("ttl", DEFAULT_TTL)
        if not 1 <= ttl <= MAX_TTL:
            raise OCPValidationError(f"TTL out of range: {ttl}", code="OCP-400")

        # Check timestamp is parseable
        try:
            datetime.fromisoformat(msg["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise OCPValidationError("Invalid timestamp format", code="OCP-400")

    def validate_signature(self, msg: dict[str, Any], public_key_bytes: bytes) -> None:
        """Verify the message signature.

        Args:
            msg: The complete OCPUMF message.
            public_key_bytes: 32-byte Ed25519 public key of the sender.

        Raises:
            OCPAuthError: If the signature is invalid.
        """
        sig_b64 = msg.get("sender", {}).get("signature", "")
        if not sig_b64:
            raise OCPAuthError("Missing signature", code="OCP-401")

        try:
            sig_bytes = b64url_decode(sig_b64)
        except Exception:
            raise OCPAuthError("Malformed signature encoding", code="OCP-401")

        # Reconstruct the signed content
        msg_for_verify = json.loads(json.dumps(msg))
        msg_for_verify["sender"]["signature"] = ""
        canonical = jsoncanon.canonicalize(msg_for_verify)
        digest = sha3_256(canonical)

        if not verify_signature(public_key_bytes, sig_bytes, digest):
            raise OCPAuthError("Signature verification failed", code="OCP-401")

    def validate(self, msg: dict[str, Any], public_key_bytes: bytes | None = None) -> None:
        """Validate structure and optionally verify signature.

        Args:
            msg: The complete OCPUMF message.
            public_key_bytes: If provided, signature is verified against this key.

        Raises:
            OCPValidationError: On structural failures.
            OCPAuthError: On signature failures.
        """
        self.validate_structure(msg)
        if public_key_bytes is not None:
            self.validate_signature(msg, public_key_bytes)


def is_expired(msg: dict[str, Any]) -> bool:
    """Check whether a message has exceeded its TTL.

    Args:
        msg: An OCPUMF message dict.

    Returns:
        ``True`` if the message is expired, ``False`` otherwise.
    """
    try:
        ts = datetime.fromisoformat(msg["timestamp"].replace("Z", "+00:00"))
        ttl = msg.get("ttl", DEFAULT_TTL)
        from datetime import timedelta
        return datetime.now(timezone.utc) > ts + timedelta(seconds=ttl)
    except Exception:
        return True


def build_ack(original_msg: dict[str, Any], sender_id: str, signing_keys: SigningKeyPair) -> dict[str, Any]:
    """Build an ACK message for a received message.

    Args:
        original_msg: The message being acknowledged.
        sender_id: The acknowledging agent's DID.
        signing_keys: The acknowledging agent's signing keys.

    Returns:
        A signed ACK OCPUMF message.
    """
    return (
        MessageBuilder(sender_id, signing_keys)
        .to(original_msg["sender"]["agent_id"])
        .type(MessageType.ACK)
        .payload({"acknowledged_message_id": original_msg["message_id"]})
        .correlate(original_msg["message_id"])
        .build()
    )


def build_error(
    code: str,
    message: str,
    reference_message_id: str,
    sender_id: str,
    signing_keys: SigningKeyPair,
    receiver_id: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an error response message.

    Args:
        code: OCP error code (e.g., ``"OCP-400"``).
        message: Human-readable error description.
        reference_message_id: The ``message_id`` of the message that caused the error.
        sender_id: The responding agent's DID.
        signing_keys: The responding agent's signing keys.
        receiver_id: The error recipient's DID.
        details: Optional additional error details.

    Returns:
        A signed error OCPUMF message.
    """
    payload: dict[str, Any] = {
        "error_code": code,
        "message": message,
        "reference_message_id": reference_message_id,
    }
    if details:
        payload["details"] = details

    return (
        MessageBuilder(sender_id, signing_keys)
        .to(receiver_id)
        .type(MessageType.ERROR)
        .payload(payload)
        .correlate(reference_message_id)
        .build()
    )
