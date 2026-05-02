"""Tests for key recovery via Shamir's Secret Sharing.

Compliance category: Key Recovery (10 tests)
"""

import itertools
import secrets

import pytest

from ocp.crypto import EncryptionKeyPair, sha3_256_hex
from ocp.exceptions import OCPRecoveryError
from ocp.identity import AgentIdentity
from ocp.recovery import (
    RecoveryManager,
    RecoveryShare,
    reconstruct_secret,
    split_secret,
)


class TestShamirSplitReconstruct:
    """Core Shamir SSS correctness over GF(2^8)."""

    def test_3_of_5(self):
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, threshold=3, num_shares=5)
        assert len(shares) == 5
        recovered = reconstruct_secret(shares[:3])
        assert recovered == secret

    def test_all_shares(self):
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, threshold=3, num_shares=5)
        assert reconstruct_secret(shares) == secret

    def test_all_t_subsets(self):
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, threshold=3, num_shares=5)
        for combo in itertools.combinations(shares, 3):
            assert reconstruct_secret(list(combo)) == secret

    def test_fewer_than_threshold_fails(self):
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, threshold=3, num_shares=5)
        wrong = reconstruct_secret(shares[:2])
        assert wrong != secret

    def test_2_of_3(self):
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, threshold=2, num_shares=3)
        for i in range(3):
            for j in range(i + 1, 3):
                assert reconstruct_secret([shares[i], shares[j]]) == secret

    def test_edge_single_byte(self):
        secret = b"\x42"
        shares = split_secret(secret, threshold=2, num_shares=3)
        assert reconstruct_secret(shares[:2]) == secret

    def test_edge_all_zeros(self):
        secret = b"\x00" * 32
        shares = split_secret(secret, threshold=3, num_shares=5)
        assert reconstruct_secret(shares[:3]) == secret

    def test_edge_all_ones(self):
        secret = b"\xff" * 32
        shares = split_secret(secret, threshold=3, num_shares=5)
        assert reconstruct_secret(shares[:3]) == secret


class TestShamirValidation:
    """Parameter validation."""

    def test_threshold_below_2_rejected(self):
        with pytest.raises(ValueError, match="Threshold"):
            split_secret(b"secret", threshold=1, num_shares=3)

    def test_shares_less_than_threshold_rejected(self):
        with pytest.raises(ValueError, match="num_shares"):
            split_secret(b"secret", threshold=5, num_shares=3)

    def test_shares_exceed_255_rejected(self):
        with pytest.raises(ValueError, match="255"):
            split_secret(b"secret", threshold=3, num_shares=256)

    def test_empty_secret_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            split_secret(b"", threshold=2, num_shares=3)

    def test_duplicate_indices_rejected(self):
        with pytest.raises(ValueError, match="Duplicate"):
            reconstruct_secret([(1, b"\x01" * 32), (1, b"\x02" * 32)])

    def test_length_mismatch_rejected(self):
        with pytest.raises(ValueError, match="length"):
            reconstruct_secret([(1, b"\x01" * 32), (2, b"\x02" * 16)])

    def test_too_few_shares_rejected(self):
        with pytest.raises(ValueError, match="at least 2"):
            reconstruct_secret([(1, b"\x01" * 32)])


class TestRecoveryManager:
    """Full recovery lifecycle."""

    def test_generate_and_recover(self):
        ident = AgentIdentity.generate(network="testnet")
        mgr = RecoveryManager(ident.agent_id, ident.signing_keys)
        shares = mgr.generate_shares(threshold=3, num_shares=5)
        assert len(shares) == 5
        assert all(isinstance(s, RecoveryShare) for s in shares)
        assert all(s.threshold == 3 for s in shares)
        assert all(s.total_shares == 5 for s in shares)
        assert all(s.key_fingerprint == mgr.key_fingerprint for s in shares)

        raw = [(s.share_index, s.share_data) for s in shares[:3]]
        recovered = RecoveryManager.reconstruct(raw, mgr.key_fingerprint)
        assert len(recovered) == 32

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv = Ed25519PrivateKey.from_private_bytes(recovered)
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert sha3_256_hex(pub)[:16] == mgr.key_fingerprint

    def test_wrong_fingerprint_rejected(self):
        ident = AgentIdentity.generate(network="testnet")
        mgr = RecoveryManager(ident.agent_id, ident.signing_keys)
        shares = mgr.generate_shares(threshold=2, num_shares=3)
        raw = [(s.share_index, s.share_data) for s in shares[:2]]
        with pytest.raises(OCPRecoveryError, match="fingerprint"):
            RecoveryManager.reconstruct(raw, "0000000000000000")

    def test_share_serialization(self):
        ident = AgentIdentity.generate(network="testnet")
        mgr = RecoveryManager(ident.agent_id, ident.signing_keys)
        shares = mgr.generate_shares(threshold=3, num_shares=5)
        for s in shares:
            d = s.to_dict()
            assert d["scheme"] == "shamir-sss-gf256"
            assert d["threshold"] == 3
            assert d["total_shares"] == 5
            assert d["agent_id"] == ident.agent_id
            assert len(d["key_fingerprint"]) == 16
            assert d["share_id"].startswith("share-")
            assert d["expires_at"] is not None


class TestEncryptedShareTransfer:
    """Encrypted share distribution to custodians."""

    def test_encrypt_decrypt_share(self):
        ident = AgentIdentity.generate(network="testnet")
        custodian = EncryptionKeyPair.generate()
        mgr = RecoveryManager(ident.agent_id, ident.signing_keys)
        shares = mgr.generate_shares(threshold=2, num_shares=3)

        encrypted = mgr.encrypt_share_for_custodian(shares[0], custodian.public_key_bytes)
        assert "ephemeral_public_key" in encrypted
        assert "nonce" in encrypted
        assert "encrypted_share" in encrypted

        decrypted = RecoveryManager.decrypt_share(encrypted, custodian.private_key)
        assert decrypted == shares[0].share_data

    def test_wrong_custodian_key_fails(self):
        ident = AgentIdentity.generate(network="testnet")
        correct = EncryptionKeyPair.generate()
        wrong = EncryptionKeyPair.generate()
        mgr = RecoveryManager(ident.agent_id, ident.signing_keys)
        shares = mgr.generate_shares(threshold=2, num_shares=3)

        encrypted = mgr.encrypt_share_for_custodian(shares[0], correct.public_key_bytes)
        with pytest.raises(Exception):
            RecoveryManager.decrypt_share(encrypted, wrong.private_key)

    def test_full_recovery_with_encryption(self):
        """End-to-end: generate → encrypt → distribute → collect → decrypt → reconstruct."""
        ident = AgentIdentity.generate(network="testnet")
        mgr = RecoveryManager(ident.agent_id, ident.signing_keys)
        shares = mgr.generate_shares(threshold=3, num_shares=5)

        custodians = [EncryptionKeyPair.generate() for _ in range(5)]
        encrypted_shares = [
            mgr.encrypt_share_for_custodian(s, c.public_key_bytes)
            for s, c in zip(shares, custodians)
        ]

        # Recover using custodians 0, 2, 4
        collected = []
        for idx in [0, 2, 4]:
            data = RecoveryManager.decrypt_share(encrypted_shares[idx], custodians[idx].private_key)
            collected.append((shares[idx].share_index, data))

        recovered = RecoveryManager.reconstruct(collected, mgr.key_fingerprint)

        restored = AgentIdentity.from_private_key(recovered, network="testnet")
        assert restored.agent_id == ident.agent_id
