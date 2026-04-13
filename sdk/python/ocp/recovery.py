"""Key recovery via Shamir's Secret Sharing over GF(2^8).

This module implements the OCP key recovery mechanism (§8.3), providing:

- Share generation: split a private key into ``n`` shares
- Share reconstruction: recover the key from any ``t`` shares
- Encrypted share distribution to custodians
- Fingerprint-based verification after reconstruction

The scheme uses Shamir's Secret Sharing over the Galois field GF(2^8)
with the AES irreducible polynomial (x^8 + x^4 + x^3 + x + 1).

**Security properties:**

- ``t-1`` compromised custodians learn zero information about the key
- No master key or backdoor exists
- Recovery uses ephemeral keys for forward secrecy
- Shares are encrypted per-custodian via ECDH + AES-256-GCM
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from ocp.constants import (
    DEFAULT_RECOVERY_SHARES,
    DEFAULT_RECOVERY_THRESHOLD,
    HKDF_INFO_RECOVERY,
    KEY_ROTATION_RECOMMENDED_SECONDS,
    MAX_RECOVERY_SHARES,
)
from ocp.crypto import (
    EncryptionKeyPair,
    SigningKeyPair,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    b64url_decode,
    b64url_encode,
    ecdh_derive_key,
    sha3_256_hex,
)
from ocp.exceptions import OCPRecoveryError


# ==========================================================================
# GF(2^8) arithmetic
# ==========================================================================

_EXP = [0] * 512
_LOG = [0] * 256
_INITIALIZED = False


def _init_gf256_tables() -> None:
    """Initialize GF(2^8) exp/log lookup tables.

    Uses the AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B.
    """
    global _INITIALIZED
    if _INITIALIZED:
        return

    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11B
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]

    _INITIALIZED = True


def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8)."""
    if a == 0 or b == 0:
        return 0
    _init_gf256_tables()
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^8)."""
    if a == 0:
        raise ZeroDivisionError("No inverse for 0 in GF(2^8)")
    _init_gf256_tables()
    return _EXP[255 - _LOG[a]]


def _gf_add(a: int, b: int) -> int:
    """Add (XOR) two elements in GF(2^8)."""
    return a ^ b


# ==========================================================================
# Polynomial evaluation
# ==========================================================================

def _eval_polynomial(coeffs: list[int], x: int) -> int:
    """Evaluate a polynomial at point x in GF(2^8).

    Args:
        coeffs: Coefficients, where coeffs[0] is the constant (secret).
        x: Evaluation point (must be non-zero for shares).

    Returns:
        The polynomial value at x.
    """
    result = 0
    for c in reversed(coeffs):
        result = _gf_add(_gf_mul(result, x), c)
    return result


# ==========================================================================
# Shamir's Secret Sharing
# ==========================================================================

def split_secret(
    secret: bytes,
    threshold: int = DEFAULT_RECOVERY_THRESHOLD,
    num_shares: int = DEFAULT_RECOVERY_SHARES,
) -> list[tuple[int, bytes]]:
    """Split a secret into Shamir shares over GF(2^8).

    For each byte of the secret, a random polynomial of degree
    ``threshold - 1`` is constructed with the byte as the constant
    term, and evaluated at ``num_shares`` distinct non-zero points.

    Args:
        secret: The secret bytes to split (e.g., 32-byte Ed25519 private key).
        threshold: Minimum shares needed to reconstruct (``t``). Must be >= 2.
        num_shares: Total shares to generate (``n``). Must be >= threshold, <= 255.

    Returns:
        List of ``(share_index, share_bytes)`` tuples. Indices are 1-based.

    Raises:
        ValueError: If parameters violate OCP constraints.
    """
    _init_gf256_tables()

    if threshold < 2:
        raise ValueError("Threshold must be >= 2 (threshold=1 is prohibited by OCP)")
    if num_shares < threshold:
        raise ValueError(f"num_shares ({num_shares}) must be >= threshold ({threshold})")
    if num_shares > MAX_RECOVERY_SHARES:
        raise ValueError(f"num_shares must be <= {MAX_RECOVERY_SHARES}")
    if len(secret) == 0:
        raise ValueError("Secret must not be empty")

    shares: list[list[int]] = [[] for _ in range(num_shares)]

    for byte_val in secret:
        coeffs = [byte_val] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for i in range(num_shares):
            x = i + 1  # x ∈ {1, 2, ..., n}, never 0
            shares[i].append(_eval_polynomial(coeffs, x))

    return [(i + 1, bytes(shares[i])) for i in range(num_shares)]


def reconstruct_secret(shares: list[tuple[int, bytes]]) -> bytes:
    """Reconstruct a secret from Shamir shares via Lagrange interpolation.

    Evaluates the Lagrange interpolating polynomial at x=0 for each
    byte position independently over GF(2^8).

    Args:
        shares: List of ``(share_index, share_bytes)`` tuples.
                Must contain at least ``threshold`` shares.

    Returns:
        The reconstructed secret bytes.

    Raises:
        ValueError: If shares are inconsistent or duplicated.
    """
    _init_gf256_tables()

    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct")

    num_bytes = len(shares[0][1])
    for idx, s in shares:
        if len(s) != num_bytes:
            raise ValueError(
                f"Share {idx} length ({len(s)}) does not match "
                f"expected length ({num_bytes})"
            )

    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("Duplicate share indices detected")

    result = bytearray(num_bytes)

    for byte_pos in range(num_bytes):
        ys = [s[1][byte_pos] for s in shares]
        secret_byte = 0

        for i, (xi, yi) in enumerate(zip(xs, ys)):
            # Lagrange basis polynomial l_i evaluated at x=0
            num = 1
            den = 1
            for j, xj in enumerate(xs):
                if i != j:
                    num = _gf_mul(num, xj)
                    den = _gf_mul(den, _gf_add(xi, xj))
            if den == 0:
                raise ValueError(f"Degenerate share set at index {xi}")
            basis = _gf_mul(num, _gf_inv(den))
            secret_byte = _gf_add(secret_byte, _gf_mul(yi, basis))

        result[byte_pos] = secret_byte

    return bytes(result)


# ==========================================================================
# Recovery Share record
# ==========================================================================

@dataclass
class RecoveryShare:
    """A single recovery share with metadata.

    Attributes:
        agent_id: The agent this share belongs to.
        share_index: 1-based index of this share.
        share_data: Raw share bytes.
        threshold: Minimum shares needed to reconstruct.
        total_shares: Total number of shares generated.
        key_fingerprint: First 16 hex chars of SHA-3-256(public_key).
        created_at: When the share was generated.
        expires_at: When the share expires.
        share_id: Unique share identifier.
    """

    agent_id: str
    share_index: int
    share_data: bytes
    threshold: int
    total_shares: int
    key_fingerprint: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    share_id: str = ""

    def __post_init__(self) -> None:
        if not self.share_id:
            short_id = self.agent_id.split("agent-")[-1][:8] if "agent-" in self.agent_id else "unknown"
            self.share_id = f"share-{short_id}-{self.share_index}"
        if self.expires_at is None:
            self.expires_at = self.created_at + timedelta(
                seconds=KEY_ROTATION_RECOMMENDED_SECONDS
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to an OCP recovery share record dict."""
        return {
            "share_id": self.share_id,
            "agent_id": self.agent_id,
            "scheme": "shamir-sss-gf256",
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "share_index": self.share_index,
            "share_data": b64url_encode(self.share_data),
            "key_fingerprint": self.key_fingerprint,
            "created_at": self.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (
                self.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                if self.expires_at else None
            ),
            "encryption": {
                "algorithm": "AES-256-GCM",
                "note": "Share is encrypted to the custodian's public key before transmission.",
            },
        }

    @property
    def is_expired(self) -> bool:
        """Check if this share has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


# ==========================================================================
# Recovery Manager
# ==========================================================================

class RecoveryManager:
    """Manages the full key recovery lifecycle.

    Handles share generation, encrypted distribution to custodians,
    and reconstruction with fingerprint verification.

    Usage::

        mgr = RecoveryManager(identity.agent_id, identity.signing_keys)

        # Generate shares
        shares = mgr.generate_shares(threshold=3, num_shares=5)

        # Encrypt for each custodian
        for share, custodian_pub in zip(shares, custodian_public_keys):
            encrypted = mgr.encrypt_share_for_custodian(share, custodian_pub)
            # ... send encrypted to custodian ...

        # Later: recover
        collected = [(idx, data) for idx, data in custodian_responses]
        private_key = RecoveryManager.reconstruct(collected, mgr.key_fingerprint)

    Args:
        agent_id: The agent's DID.
        signing_keys: The agent's current signing keypair.
    """

    def __init__(self, agent_id: str, signing_keys: SigningKeyPair) -> None:
        self._agent_id = agent_id
        self._signing_keys = signing_keys
        self._key_fingerprint = sha3_256_hex(signing_keys.public_key_bytes)[:16]

    @property
    def key_fingerprint(self) -> str:
        """First 16 hex chars of SHA-3-256(public_key)."""
        return self._key_fingerprint

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def generate_shares(
        self,
        threshold: int = DEFAULT_RECOVERY_THRESHOLD,
        num_shares: int = DEFAULT_RECOVERY_SHARES,
    ) -> list[RecoveryShare]:
        """Split the agent's signing private key into Shamir shares.

        Args:
            threshold: Minimum shares required to reconstruct.
            num_shares: Total shares to produce.

        Returns:
            List of :class:`RecoveryShare` objects ready for distribution.
        """
        raw_private = self._signing_keys.private_key_bytes
        raw_shares = split_secret(raw_private, threshold, num_shares)

        return [
            RecoveryShare(
                agent_id=self._agent_id,
                share_index=idx,
                share_data=data,
                threshold=threshold,
                total_shares=num_shares,
                key_fingerprint=self._key_fingerprint,
            )
            for idx, data in raw_shares
        ]

    def encrypt_share_for_custodian(
        self,
        share: RecoveryShare,
        custodian_public_key_bytes: bytes,
    ) -> dict[str, str]:
        """Encrypt a share for a specific custodian.

        Uses an ephemeral X25519 keypair and ECDH + AES-256-GCM.

        Args:
            share: The recovery share to encrypt.
            custodian_public_key_bytes: Custodian's 32-byte X25519 public key.

        Returns:
            Dict with ``ephemeral_public_key``, ``nonce``, and
            ``encrypted_share`` (all base64url-encoded).
        """
        ephemeral = EncryptionKeyPair.generate()
        aes_key = ecdh_derive_key(
            ephemeral.private_key,
            custodian_public_key_bytes,
            info=HKDF_INFO_RECOVERY,
        )
        nonce, ct = aes_gcm_encrypt(aes_key, share.share_data)

        return {
            "ephemeral_public_key": ephemeral.public_key_b64url,
            "nonce": b64url_encode(nonce),
            "encrypted_share": b64url_encode(ct),
        }

    @staticmethod
    def decrypt_share(
        encrypted: dict[str, str],
        custodian_private_key: Any,  # X25519PrivateKey
    ) -> bytes:
        """Decrypt a share received from a custodian.

        Args:
            encrypted: Dict with ``ephemeral_public_key``, ``nonce``,
                       ``encrypted_share``.
            custodian_private_key: The custodian's X25519 private key.

        Returns:
            Decrypted share bytes.
        """
        eph_pub = b64url_decode(encrypted["ephemeral_public_key"])
        aes_key = ecdh_derive_key(
            custodian_private_key,
            eph_pub,
            info=HKDF_INFO_RECOVERY,
        )
        nonce = b64url_decode(encrypted["nonce"])
        ct = b64url_decode(encrypted["encrypted_share"])
        return aes_gcm_decrypt(aes_key, nonce, ct)

    @staticmethod
    def reconstruct(
        shares: list[tuple[int, bytes]],
        expected_fingerprint: str,
    ) -> bytes:
        """Reconstruct the private key from collected shares.

        After reconstruction, the derived public key's fingerprint is
        compared against the expected value to verify correctness.

        Args:
            shares: List of ``(share_index, share_bytes)`` from custodians.
            expected_fingerprint: First 16 hex chars of SHA-3-256(public_key).

        Returns:
            Reconstructed 32-byte Ed25519 private key.

        Raises:
            OCPRecoveryError: If reconstruction or verification fails.
        """
        raw_private = reconstruct_secret(shares)

        # Verify: derive the public key and check the fingerprint
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        try:
            priv = Ed25519PrivateKey.from_private_bytes(raw_private)
        except Exception as e:
            raise OCPRecoveryError(
                f"Reconstructed bytes are not a valid Ed25519 key: {e}"
            )

        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        actual_fp = sha3_256_hex(pub_bytes)[:16]

        if actual_fp != expected_fingerprint:
            raise OCPRecoveryError(
                f"Key fingerprint mismatch: expected {expected_fingerprint}, "
                f"got {actual_fp}. Shares may be corrupted or from different keys."
            )

        return raw_private

    def build_recovery_request_payload(
        self,
        ephemeral_encryption_key: EncryptionKeyPair,
        secondary_key: SigningKeyPair | None = None,
    ) -> dict[str, Any]:
        """Build a ``recovery_request`` message payload.

        Args:
            ephemeral_encryption_key: Fresh X25519 keypair for response encryption.
            secondary_key: Pre-registered secondary recovery signing key.

        Returns:
            Payload dict for a ``recovery_request`` OCPUMF message.
        """
        payload: dict[str, Any] = {
            "agent_id": self._agent_id,
            "key_fingerprint": self._key_fingerprint,
            "ephemeral_public_key": ephemeral_encryption_key.public_key_b64url,
        }

        if secondary_key:
            sign_data = (
                f"{self._agent_id}||{self._key_fingerprint}||"
                f"{ephemeral_encryption_key.public_key_b64url}"
            ).encode()
            from ocp.crypto import sha3_256
            sig = secondary_key.sign(sha3_256(sign_data))
            payload["proof"] = {
                "type": "secondary_key_signature",
                "secondary_key_id": f"{self._agent_id}#recovery-key-1",
                "signature": b64url_encode(sig),
            }
        else:
            payload["proof"] = {
                "type": "out_of_band",
                "note": "Identity must be verified through external channel",
            }

        return payload
