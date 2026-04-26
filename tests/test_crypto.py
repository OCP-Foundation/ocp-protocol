"""Tests for cryptographic primitives.

Compliance category: Cryptographic Primitives (12 tests)
"""

import pytest

from ocp.crypto import (
    SigningKeyPair,
    EncryptionKeyPair,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    b64url_encode,
    b64url_decode,
    ecdh_derive_key,
    encrypt_payload,
    decrypt_payload,
    generate_message_id,
    generate_nonce,
    sha3_256,
    sha3_256_hex,
    verify_signature,
)


class TestSHA3:
    """FIPS 202 — SHA-3-256."""

    def test_output_length(self):
        assert len(sha3_256(b"test")) == 32

    def test_hex_output_length(self):
        assert len(sha3_256_hex(b"test")) == 64

    def test_deterministic(self):
        assert sha3_256(b"ocp") == sha3_256(b"ocp")

    def test_different_inputs_different_hashes(self):
        assert sha3_256(b"a") != sha3_256(b"b")

    def test_empty_input(self):
        h = sha3_256(b"")
        assert len(h) == 32
        assert h == sha3_256(b"")


class TestEd25519:
    """RFC 8032 — Ed25519 signing and verification."""

    def test_sign_and_verify(self, signing_keys):
        data = b"hello ocp protocol"
        sig = signing_keys.sign(data)
        assert len(sig) == 64
        signing_keys.verify(sig, data)  # should not raise

    def test_verify_wrong_data_fails(self, signing_keys):
        sig = signing_keys.sign(b"correct data")
        with pytest.raises(Exception):
            signing_keys.verify(sig, b"wrong data")

    def test_verify_with_raw_public_key(self, signing_keys):
        data = b"test payload"
        sig = signing_keys.sign(data)
        assert verify_signature(signing_keys.public_key_bytes, sig, data)

    def test_wrong_key_rejects(self):
        keys_a = SigningKeyPair.generate()
        keys_b = SigningKeyPair.generate()
        sig = keys_a.sign(b"data")
        assert not verify_signature(keys_b.public_key_bytes, sig, b"data")

    def test_from_private_bytes_roundtrip(self, signing_keys):
        raw = signing_keys.private_key_bytes
        restored = SigningKeyPair.from_private_bytes(raw)
        assert restored.public_key_bytes == signing_keys.public_key_bytes
        sig = restored.sign(b"test")
        signing_keys.verify(sig, b"test")

    def test_public_key_is_32_bytes(self, signing_keys):
        assert len(signing_keys.public_key_bytes) == 32

    def test_private_key_is_32_bytes(self, signing_keys):
        assert len(signing_keys.private_key_bytes) == 32

    def test_multibase_encoding(self, signing_keys):
        mb = signing_keys.public_key_multibase
        assert mb.startswith("z")
        assert len(mb) > 1


class TestX25519:
    """RFC 7748 — X25519 ECDH key exchange."""

    def test_shared_secret_agreement(self):
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        key_a = ecdh_derive_key(alice.private_key, bob.public_key_bytes)
        key_b = ecdh_derive_key(bob.private_key, alice.public_key_bytes)
        assert key_a == key_b
        assert len(key_a) == 32

    def test_different_peers_different_secrets(self):
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        carol = EncryptionKeyPair.generate()
        key_ab = ecdh_derive_key(alice.private_key, bob.public_key_bytes)
        key_ac = ecdh_derive_key(alice.private_key, carol.public_key_bytes)
        assert key_ab != key_ac

    def test_custom_info_string(self):
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        k1 = ecdh_derive_key(alice.private_key, bob.public_key_bytes, info=b"context-a")
        k2 = ecdh_derive_key(alice.private_key, bob.public_key_bytes, info=b"context-b")
        assert k1 != k2


class TestAESGCM:
    """NIST SP 800-38D — AES-256-GCM."""

    def test_encrypt_decrypt_roundtrip(self):
        key = sha3_256(b"test-key")
        pt = b"sensitive knowledge payload"
        nonce, ct = aes_gcm_encrypt(key, pt)
        assert len(nonce) == 12
        result = aes_gcm_decrypt(key, nonce, ct)
        assert result == pt

    def test_wrong_key_fails(self):
        key = sha3_256(b"correct-key")
        wrong = sha3_256(b"wrong-key")
        nonce, ct = aes_gcm_encrypt(key, b"secret")
        with pytest.raises(Exception):
            aes_gcm_decrypt(wrong, nonce, ct)

    def test_wrong_nonce_fails(self):
        key = sha3_256(b"key")
        nonce, ct = aes_gcm_encrypt(key, b"data")
        wrong_nonce = b"\x00" * 12
        if wrong_nonce != nonce:
            with pytest.raises(Exception):
                aes_gcm_decrypt(key, wrong_nonce, ct)

    def test_tampered_ciphertext_fails(self):
        key = sha3_256(b"key")
        nonce, ct = aes_gcm_encrypt(key, b"data")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            aes_gcm_decrypt(key, nonce, bytes(tampered))

    def test_empty_plaintext(self):
        key = sha3_256(b"key")
        nonce, ct = aes_gcm_encrypt(key, b"")
        assert aes_gcm_decrypt(key, nonce, ct) == b""

    def test_large_plaintext(self):
        key = sha3_256(b"key")
        pt = b"x" * 1_000_000
        nonce, ct = aes_gcm_encrypt(key, pt)
        assert aes_gcm_decrypt(key, nonce, ct) == pt


class TestMessageEncryption:
    """OCP-SPEC §7.3 — Full message-level encryption."""

    def test_encrypt_decrypt_payload(self):
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        pt = b'{"knowledge_type": "insight", "data": "test"}'
        encrypted = encrypt_payload(pt, bob.public_key_bytes)
        assert "algorithm" in encrypted
        assert "key_exchange" in encrypted
        assert "nonce" in encrypted
        assert "ephemeral_public_key" in encrypted
        assert "ciphertext" in encrypted
        result = decrypt_payload(encrypted, bob.private_key)
        assert result == pt

    def test_wrong_recipient_fails(self):
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        carol = EncryptionKeyPair.generate()
        encrypted = encrypt_payload(b"secret", bob.public_key_bytes)
        with pytest.raises(Exception):
            decrypt_payload(encrypted, carol.private_key)


class TestBase64url:
    """RFC 4648 §5 — Base64url encoding."""

    def test_roundtrip(self):
        data = b"\x00\xff\x80test\xfe"
        assert b64url_decode(b64url_encode(data)) == data

    def test_no_padding(self):
        encoded = b64url_encode(b"test")
        assert "=" not in encoded

    def test_url_safe_chars(self):
        encoded = b64url_encode(b"\xff\xfe\xfd\xfc")
        assert "+" not in encoded
        assert "/" not in encoded

    def test_empty_input(self):
        assert b64url_decode(b64url_encode(b"")) == b""


class TestGenerators:
    """Nonce and ID generation."""

    def test_message_id_format(self):
        mid = generate_message_id()
        assert mid.startswith("msg-")
        parts = mid.split("-")
        assert len(parts) == 5  # msg, 8hex, 4hex, 4hex (prefix split)

    def test_nonce_uniqueness(self):
        nonces = {generate_nonce() for _ in range(1000)}
        assert len(nonces) == 1000

    def test_nonce_length(self):
        n = generate_nonce(32)
        decoded = b64url_decode(n)
        assert len(decoded) == 32
