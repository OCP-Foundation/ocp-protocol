"""Cryptographic primitives for OCP.

This module provides the core cryptographic operations required by the
OCP specification:

- **Ed25519** signing and verification (RFC 8032)
- **X25519** Diffie-Hellman key exchange (RFC 7748)
- **AES-256-GCM** symmetric encryption (NIST SP 800-38D)
- **SHA-3-256** hashing (FIPS 202)
- **HKDF-SHA-256** key derivation (RFC 5869)
- Agent ID derivation from public keys
- Nonce and message ID generation

All binary outputs are base64url-encoded (RFC 4648 §5, no padding)
when serialized to strings.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import uuid
from dataclasses import dataclass
from typing import Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ocp.constants import HKDF_INFO_AES_KEY


# ==========================================================================
# Base64url helpers
# ==========================================================================

def b64url_encode(data: bytes) -> str:
    """Encode bytes to a base64url string without padding.

    Args:
        data: Raw bytes to encode.

    Returns:
        Base64url-encoded string with ``=`` padding stripped.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decode a base64url string to bytes.

    Handles missing padding automatically.

    Args:
        s: Base64url-encoded string, with or without ``=`` padding.

    Returns:
        Decoded bytes.
    """
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ==========================================================================
# SHA-3 hashing
# ==========================================================================

def sha3_256(data: bytes) -> bytes:
    """Compute the SHA-3-256 hash of *data*.

    Args:
        data: Input bytes.

    Returns:
        32-byte digest.
    """
    return hashlib.sha3_256(data).digest()


def sha3_256_hex(data: bytes) -> str:
    """Compute the SHA-3-256 hash and return a lowercase hex string.

    Args:
        data: Input bytes.

    Returns:
        64-character hexadecimal string.
    """
    return hashlib.sha3_256(data).hexdigest()


# ==========================================================================
# Ed25519 signing
# ==========================================================================

@dataclass(frozen=True)
class SigningKeyPair:
    """An Ed25519 signing keypair.

    The private key is used to sign OCP messages and vouches.
    The public key is published in the agent's DID Document.

    Attributes:
        private_key: The Ed25519 private key object.
        public_key: The corresponding Ed25519 public key object.
    """

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> Self:
        """Generate a new Ed25519 keypair from the OS CSPRNG.

        Returns:
            A fresh :class:`SigningKeyPair`.
        """
        priv = Ed25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())

    @classmethod
    def from_private_bytes(cls, data: bytes) -> Self:
        """Restore a keypair from raw 32-byte private key material.

        Args:
            data: 32 bytes of Ed25519 private key.

        Returns:
            The reconstructed :class:`SigningKeyPair`.
        """
        priv = Ed25519PrivateKey.from_private_bytes(data)
        return cls(private_key=priv, public_key=priv.public_key())

    def sign(self, data: bytes) -> bytes:
        """Sign *data* with the private key.

        Args:
            data: Arbitrary bytes to sign.

        Returns:
            64-byte Ed25519 signature.
        """
        return self.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> None:
        """Verify a signature against the public key.

        Args:
            signature: 64-byte Ed25519 signature.
            data: The original data that was signed.

        Raises:
            cryptography.exceptions.InvalidSignature: If verification fails.
        """
        self.public_key.verify(signature, data)

    @property
    def private_key_bytes(self) -> bytes:
        """Raw 32-byte private key.

        .. warning::
            Handle with care. Never transmit over OCP or log.
        """
        return self.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte public key."""
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_key_b64url(self) -> str:
        """Base64url-encoded public key."""
        return b64url_encode(self.public_key_bytes)

    @property
    def public_key_multibase(self) -> str:
        """Multibase-encoded public key with ``z`` (base58btc) prefix.

        Note:
            This is a simplified encoding. A production implementation
            should use proper multibase with multicodec prefix per the
            W3C DID specification.
        """
        return "z" + b64url_encode(self.public_key_bytes)


def verify_signature(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 signature given raw public key bytes.

    Args:
        public_key_bytes: 32-byte Ed25519 public key.
        signature: 64-byte Ed25519 signature.
        data: The original signed data.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, data)
        return True
    except Exception:
        return False


# ==========================================================================
# X25519 key exchange
# ==========================================================================

@dataclass(frozen=True)
class EncryptionKeyPair:
    """An X25519 key exchange keypair.

    Used for ECDH shared secret derivation in message encryption
    and recovery share encryption.

    Attributes:
        private_key: The X25519 private key object.
        public_key: The corresponding X25519 public key object.
    """

    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    @classmethod
    def generate(cls) -> Self:
        """Generate a new X25519 keypair from the OS CSPRNG.

        Returns:
            A fresh :class:`EncryptionKeyPair`.
        """
        priv = X25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte public key."""
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_key_b64url(self) -> str:
        """Base64url-encoded public key."""
        return b64url_encode(self.public_key_bytes)


def ecdh_derive_key(
    our_private: X25519PrivateKey,
    their_public_bytes: bytes,
    info: bytes = HKDF_INFO_AES_KEY,
) -> bytes:
    """Perform ECDH key exchange and derive a 256-bit AES key.

    Uses X25519 for the shared secret and HKDF-SHA-256 for key
    derivation, as specified in OCP §7.3.

    Args:
        our_private: Our X25519 private key.
        their_public_bytes: The peer's 32-byte X25519 public key.
        info: HKDF info parameter. Defaults to ``b"ocp-v1-aes-key"``.

    Returns:
        32-byte derived AES key.
    """
    their_public = X25519PublicKey.from_public_bytes(their_public_bytes)
    shared_secret = our_private.exchange(their_public)
    derived = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return derived


# ==========================================================================
# AES-256-GCM encryption
# ==========================================================================

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM.

    Args:
        key: 32-byte AES key.
        plaintext: Data to encrypt.
        aad: Optional additional authenticated data.

    Returns:
        Tuple of ``(nonce, ciphertext)``. The nonce is 12 bytes (96 bits).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt AES-256-GCM ciphertext.

    Args:
        key: 32-byte AES key.
        nonce: 12-byte nonce used during encryption.
        ciphertext: Encrypted data with authentication tag.
        aad: Optional additional authenticated data (must match encryption).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If decryption or authentication fails.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ==========================================================================
# Encrypt / decrypt full messages
# ==========================================================================

def encrypt_payload(
    plaintext: bytes,
    recipient_public_key_bytes: bytes,
    info: bytes = HKDF_INFO_AES_KEY,
) -> dict[str, str]:
    """Encrypt a payload for a specific recipient.

    Generates an ephemeral X25519 keypair, derives a shared AES key
    via ECDH + HKDF, and encrypts with AES-256-GCM.

    Args:
        plaintext: Bytes to encrypt.
        recipient_public_key_bytes: Recipient's 32-byte X25519 public key.
        info: HKDF info string.

    Returns:
        Dict with ``algorithm``, ``key_exchange``, ``nonce``,
        ``ephemeral_public_key``, and ``ciphertext`` — all string values
        base64url-encoded where applicable.
    """
    ephemeral = EncryptionKeyPair.generate()
    aes_key = ecdh_derive_key(ephemeral.private_key, recipient_public_key_bytes, info)
    nonce, ct = aes_gcm_encrypt(aes_key, plaintext)
    return {
        "algorithm": "AES-256-GCM",
        "key_exchange": "ECDH-X25519",
        "nonce": b64url_encode(nonce),
        "ephemeral_public_key": ephemeral.public_key_b64url,
        "ciphertext": b64url_encode(ct),
    }


def decrypt_payload(
    encrypted: dict[str, str],
    our_private_key: X25519PrivateKey,
    info: bytes = HKDF_INFO_AES_KEY,
) -> bytes:
    """Decrypt a payload encrypted with :func:`encrypt_payload`.

    Args:
        encrypted: Dict as returned by :func:`encrypt_payload`.
        our_private_key: Our X25519 private key.
        info: HKDF info string (must match what was used to encrypt).

    Returns:
        Decrypted plaintext bytes.
    """
    eph_pub = b64url_decode(encrypted["ephemeral_public_key"])
    aes_key = ecdh_derive_key(our_private_key, eph_pub, info)
    nonce = b64url_decode(encrypted["nonce"])
    ct = b64url_decode(encrypted["ciphertext"])
    return aes_gcm_decrypt(aes_key, nonce, ct)


# ==========================================================================
# Agent ID derivation
# ==========================================================================

def derive_agent_id(public_key_bytes: bytes, network: str = "mainnet") -> str:
    """Derive an OCP Agent DID from a public key.

    Takes the first 48 bits (6 bytes) of SHA-3-256(public_key) and
    formats as ``did:ocp:<network>:agent-<12 hex chars>``.

    Args:
        public_key_bytes: 32-byte Ed25519 public key.
        network: Network identifier (``"mainnet"`` or ``"testnet"``).

    Returns:
        A DID string such as ``did:ocp:mainnet:agent-a3f9b2c1d4e5``.
    """
    h = sha3_256(public_key_bytes)
    agent_hex = h[:6].hex()
    return f"did:ocp:{network}:agent-{agent_hex}"


# ==========================================================================
# Nonce and ID generation
# ==========================================================================

def generate_nonce(length: int = 32) -> str:
    """Generate a cryptographically secure random nonce as base64url.

    Args:
        length: Number of random bytes (default 32 = 256 bits).

    Returns:
        Base64url-encoded nonce string.
    """
    return b64url_encode(secrets.token_bytes(length))


def generate_message_id() -> str:
    """Generate a truncated UUIDv4 message ID per OCPUMF spec.

    Format: ``msg-<8hex>-<4hex>-<4hex>-<4hex>``

    Returns:
        A unique message identifier string.
    """
    u = uuid.uuid4().hex
    return f"msg-{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}"


def generate_uuid_short(prefix: str = "") -> str:
    """Generate a short prefixed UUID for bonds, tasks, insights, etc.

    Args:
        prefix: String prefix (e.g., ``"bond-"``, ``"task-"``).

    Returns:
        Prefixed identifier string.
    """
    u = uuid.uuid4().hex
    return f"{prefix}{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}"
    