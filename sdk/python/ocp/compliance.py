"""OCP Compliance Checker.

Runs a subset of the OCP Compliance Test Suite to verify that a local
SDK installation produces conforming outputs.
"""

from __future__ import annotations

import sys
import traceback


def _test_identity() -> bool:
    """Verify DID generation and format."""
    from ocp.identity import AgentIdentity, validate_did
    import re

    ident = AgentIdentity.generate(network="testnet")
    assert validate_did(ident.agent_id), f"Invalid DID: {ident.agent_id}"
    assert ident.agent_id.startswith("did:ocp:testnet:agent-")

    doc = ident.did_document("wss://test.example.com/ocp/v1/ws", ["cap:nlp:test"])
    d = doc.to_dict()
    assert "https://www.w3.org/ns/did/v1" in d["@context"]
    assert d["verificationMethod"][0]["type"] == "Ed25519VerificationKey2020"

    # Uniqueness
    ids = {AgentIdentity.generate().agent_id for _ in range(50)}
    assert len(ids) == 50, "Duplicate DIDs generated"
    return True


def _test_crypto() -> bool:
    """Verify cryptographic operations."""
    from ocp.crypto import (
        SigningKeyPair, EncryptionKeyPair, aes_gcm_encrypt, aes_gcm_decrypt,
        ecdh_derive_key, sha3_256, b64url_encode, b64url_decode,
    )

    # Ed25519
    keys = SigningKeyPair.generate()
    sig = keys.sign(b"test data")
    keys.verify(sig, b"test data")

    # X25519 ECDH
    a = EncryptionKeyPair.generate()
    b = EncryptionKeyPair.generate()
    k1 = ecdh_derive_key(a.private_key, b.public_key_bytes)
    k2 = ecdh_derive_key(b.private_key, a.public_key_bytes)
    assert k1 == k2, "ECDH shared secrets don't match"

    # AES-GCM
    key = sha3_256(b"test-key")
    nonce, ct = aes_gcm_encrypt(key, b"plaintext")
    pt = aes_gcm_decrypt(key, nonce, ct)
    assert pt == b"plaintext"

    # Base64url roundtrip
    data = b"\x00\xff\x80test"
    assert b64url_decode(b64url_encode(data)) == data
    return True


def _test_messages() -> bool:
    """Verify message building and validation."""
    from ocp.identity import AgentIdentity
    from ocp.messages import MessageBuilder, MessageType, MessageValidator

    a = AgentIdentity.generate(network="testnet")
    b = AgentIdentity.generate(network="testnet")

    msg = (
        MessageBuilder(a.agent_id, a.signing_keys)
        .to(b.agent_id)
        .type(MessageType.DISCOVERY_PING)
        .payload({"test": True})
        .build()
    )

    validator = MessageValidator()
    validator.validate(msg, a.signing_keys.public_key_bytes)
    return True


def _test_pvl() -> bool:
    """Verify Privacy Validation Layer."""
    from ocp.pvl import validate_knowledge_payload

    # PII detection
    result = validate_knowledge_payload({
        "knowledge_type": "insight",
        "insight_id": "ins-test",
        "topic": "test",
        "confidence": 0.9,
        "anonymized": True,
        "payload": {"description": "Contact john@example.com"},
        "provenance": {"source_agent": "did:ocp:testnet:agent-aabbccddeeff", "timestamp": "2026-01-01T00:00:00Z"},
    })
    assert not result.passed and result.rejection_code == "PVL-001"

    # Clean payload passes
    result = validate_knowledge_payload({
        "knowledge_type": "insight",
        "insight_id": "ins-test",
        "topic": "test",
        "confidence": 0.9,
        "anonymized": True,
        "payload": {"description": "A clean finding"},
        "provenance": {"source_agent": "did:ocp:testnet:agent-aabbccddeeff", "timestamp": "2026-01-01T00:00:00Z"},
    })
    assert result.passed
    return True


def _test_recovery() -> bool:
    """Verify Shamir's Secret Sharing."""
    from ocp.recovery import split_secret, reconstruct_secret
    import secrets as sec

    secret = sec.token_bytes(32)
    shares = split_secret(secret, threshold=3, num_shares=5)
    recovered = reconstruct_secret(shares[:3])
    assert recovered == secret, "SSS reconstruction failed"

    import itertools
    for combo in itertools.combinations(shares, 3):
        assert reconstruct_secret(list(combo)) == secret
    return True


def _test_consensus() -> bool:
    """Verify consensus protocol."""
    from ocp.consensus import ConsensusConfig, ConsensusRound, Vote

    r = ConsensusRound(ConsensusConfig(
        topic="Test", options=["a", "b"], min_participants=2, threshold=0.6,
    ))
    assert r.cast_vote(Vote(voter_id="x", option="a", confidence=0.9, trust_score=0.8))
    assert r.cast_vote(Vote(voter_id="y", option="a", confidence=0.8, trust_score=0.7))
    assert not r.cast_vote(Vote(voter_id="x", option="b", confidence=0.5, trust_score=0.5))  # dup

    result = r.resolve()
    assert result.winner == "a"
    assert result.reached_quorum
    return True


def main() -> None:
    """Run the OCP compliance check suite."""
    tests = [
        ("Identity & DID", _test_identity),
        ("Cryptographic Primitives", _test_crypto),
        ("Message Building & Validation", _test_messages),
        ("Privacy Validation Layer", _test_pvl),
        ("Key Recovery (Shamir SSS)", _test_recovery),
        ("Consensus Protocol", _test_consensus),
    ]

    print("OCP Compliance Check — SDK v1.0.0")
    print("=" * 50)

    passed = 0
    failed = 0

    for name, test_fn in tests:
        try:
            result = test_fn()
            if result:
                print(f"  ✓ {name}")
                passed += 1
            else:
                print(f"  ✗ {name} — returned False")
                failed += 1
        except Exception as e:
            print(f"  ✗ {name} — {e}")
            traceback.print_exc()
            failed += 1

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
    