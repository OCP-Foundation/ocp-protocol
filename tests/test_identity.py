"""Tests for OCP agent identity — DID generation, format, documents, rotation.

Compliance category: Identity & DID (6 tests)
"""

import re

import pytest

from ocp.identity import AgentIdentity, DIDDocument, validate_did
from ocp.crypto import derive_agent_id, SigningKeyPair


class TestDIDFormat:
    """OCP-SPEC §4.1 — DID format: did:ocp:<network>:agent-<12 hex chars>."""

    PATTERN = re.compile(r"^did:ocp:[a-z]+:agent-[0-9a-f]{12}$")

    def test_mainnet_format(self):
        ident = AgentIdentity.generate(network="mainnet")
        assert self.PATTERN.match(ident.agent_id), f"Invalid DID: {ident.agent_id}"

    def test_testnet_format(self):
        ident = AgentIdentity.generate(network="testnet")
        assert ident.agent_id.startswith("did:ocp:testnet:agent-")
        assert self.PATTERN.match(ident.agent_id)

    def test_validate_did_accepts_valid(self):
        assert validate_did("did:ocp:mainnet:agent-aabbccddeeff")

    def test_validate_did_rejects_invalid(self):
        assert not validate_did("not-a-did")
        assert not validate_did("did:ocp:mainnet:agent-short")
        assert not validate_did("did:ocp:mainnet:agent-AABBCCDDEEFF")  # uppercase
        assert not validate_did("")


class TestDIDDerivation:
    """OCP-SPEC §4.1.1 — DID derived from SHA-3-256(public_key)[:6]."""

    def test_deterministic(self, signing_keys):
        id1 = derive_agent_id(signing_keys.public_key_bytes, "mainnet")
        id2 = derive_agent_id(signing_keys.public_key_bytes, "mainnet")
        assert id1 == id2

    def test_different_keys_different_ids(self):
        k1 = SigningKeyPair.generate()
        k2 = SigningKeyPair.generate()
        assert derive_agent_id(k1.public_key_bytes) != derive_agent_id(k2.public_key_bytes)

    def test_uniqueness_at_scale(self):
        ids = {AgentIdentity.generate().agent_id for _ in range(200)}
        assert len(ids) == 200, f"Collision: only {len(ids)} unique DIDs from 200"


class TestDIDDocument:
    """OCP-SPEC §4.1.2 — DID Document structure and W3C compliance."""

    def test_required_fields(self, identity):
        doc = identity.did_document(
            service_endpoint="wss://test.example.com/ocp/v1/ws",
            capabilities=["cap:nlp:classification"],
        )
        d = doc.to_dict()
        assert "https://www.w3.org/ns/did/v1" in d["@context"]
        assert "https://ocp.foundation/ns/ocp/v1" in d["@context"]
        assert d["id"] == identity.agent_id
        assert len(d["verificationMethod"]) >= 1
        assert d["verificationMethod"][0]["type"] == "Ed25519VerificationKey2020"
        assert d["verificationMethod"][0]["controller"] == identity.agent_id
        assert len(d["authentication"]) >= 1
        assert len(d["service"]) >= 1
        assert d["service"][0]["type"] == "OCPMessaging"
        assert d["service"][0]["serviceEndpoint"] == "wss://test.example.com/ocp/v1/ws"
        assert d["capabilityDeclaration"] == ["cap:nlp:classification"]

    def test_empty_optionals_omitted(self, identity):
        doc = identity.did_document(service_endpoint="https://test.example.com")
        d = doc.to_dict()
        assert "capabilityDeclaration" not in d
        assert "trustAttestations" not in d
        assert "revocation" not in d

    def test_recovery_keys_included(self, identity):
        recovery_key = SigningKeyPair.generate()
        doc = identity.did_document(
            service_endpoint="https://test.example.com",
            recovery_keys=[{"publicKeyMultibase": recovery_key.public_key_multibase}],
        )
        d = doc.to_dict()
        recovery_methods = [m for m in d["verificationMethod"] if m.get("purpose") == "recovery"]
        assert len(recovery_methods) == 1
        assert recovery_methods[0]["publicKeyMultibase"] == recovery_key.public_key_multibase

    def test_roundtrip_serialization(self, identity):
        doc = identity.did_document(
            service_endpoint="wss://test.example.com/ocp/v1/ws",
            capabilities=["cap:nlp:classification", "cap:vision:imaging"],
        )
        d = doc.to_dict()
        restored = DIDDocument.from_dict(d)
        assert restored.agent_id == doc.agent_id
        assert restored.service_endpoint == doc.service_endpoint
        assert restored.capabilities == doc.capabilities


class TestKeyRotation:
    """OCP-SPEC §8.2 — Key rotation preserves agent ID."""

    def test_agent_id_survives_rotation(self, identity):
        original_id = identity.agent_id
        old_key = identity.rotate_signing_key()
        assert identity.agent_id == original_id
        assert old_key in identity.previous_keys
        assert identity.signing_keys != old_key

    def test_key_fingerprint_changes(self, identity):
        fp_before = identity.key_fingerprint
        identity.rotate_signing_key()
        fp_after = identity.key_fingerprint
        assert fp_before != fp_after

    def test_restore_from_private_key(self, identity):
        raw = identity.signing_keys.private_key_bytes
        restored = AgentIdentity.from_private_key(raw, network="testnet")
        assert restored.agent_id == identity.agent_id
        assert restored.key_fingerprint == identity.key_fingerprint
