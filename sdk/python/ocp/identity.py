"""Agent identity management.

This module handles:

- Generating new agent identities (Ed25519 + X25519 keypairs, DID derivation)
- Building W3C-compliant DID Documents
- DID resolution strategies
- Key rotation support
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ocp.constants import NETWORK_MAINNET
from ocp.crypto import (
    EncryptionKeyPair,
    SigningKeyPair,
    derive_agent_id,
    sha3_256_hex,
)

# Regex for validating OCP DIDs
DID_PATTERN = re.compile(r"^did:ocp:[a-z]+:agent-[0-9a-f]{12}$")


def validate_did(did: str) -> bool:
    """Check whether a string is a valid OCP DID.

    Args:
        did: Candidate DID string.

    Returns:
        ``True`` if valid, ``False`` otherwise.
    """
    return bool(DID_PATTERN.match(did))


@dataclass
class DIDDocument:
    """W3C DID Document extended for OCP.

    This is the public identity document for an agent, published at a
    resolvable URL or stored in the Agent Registry.

    Attributes:
        agent_id: The agent's DID.
        public_key_multibase: Multibase-encoded Ed25519 public key.
        service_endpoint: Primary OCP messaging endpoint URL.
        capabilities: List of capability identifiers the agent supports.
        trust_attestations: Vouch records from other agents.
        revoked_keys: List of revoked key records.
        recovery_keys: Optional secondary recovery key entries.
    """

    agent_id: str
    public_key_multibase: str
    service_endpoint: str
    capabilities: list[str] = field(default_factory=list)
    trust_attestations: list[dict[str, Any]] = field(default_factory=list)
    revoked_keys: list[dict[str, str]] = field(default_factory=list)
    recovery_keys: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a W3C-compliant DID Document dict.

        Returns:
            JSON-serializable dict conforming to the OCP DID Document schema.
        """
        doc: dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://opencognitionprotocol.org/ns/ocp/v1",
            ],
            "id": self.agent_id,
            "verificationMethod": [
                {
                    "id": f"{self.agent_id}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": self.agent_id,
                    "publicKeyMultibase": self.public_key_multibase,
                }
            ],
            "authentication": [f"{self.agent_id}#key-1"],
            "service": [
                {
                    "id": f"{self.agent_id}#ocp-endpoint",
                    "type": "OCPMessaging",
                    "serviceEndpoint": self.service_endpoint,
                }
            ],
        }

        if self.capabilities:
            doc["capabilityDeclaration"] = self.capabilities

        if self.trust_attestations:
            doc["trustAttestations"] = self.trust_attestations

        if self.revoked_keys:
            doc["revocation"] = self.revoked_keys

        # Recovery keys are added as additional verificationMethod entries
        for i, rk in enumerate(self.recovery_keys):
            method = {
                "id": f"{self.agent_id}#recovery-key-{i + 1}",
                "type": "Ed25519VerificationKey2020",
                "controller": self.agent_id,
                "publicKeyMultibase": rk["publicKeyMultibase"],
                "purpose": "recovery",
            }
            doc["verificationMethod"].append(method)

        return doc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DIDDocument:
        """Deserialize from a DID Document dict.

        Args:
            data: Parsed JSON DID Document.

        Returns:
            A :class:`DIDDocument` instance.
        """
        vm = data.get("verificationMethod", [])
        primary_key = vm[0]["publicKeyMultibase"] if vm else ""

        service = data.get("service", [])
        endpoint = service[0]["serviceEndpoint"] if service else ""

        recovery = [
            {"publicKeyMultibase": m["publicKeyMultibase"]}
            for m in vm
            if m.get("purpose") == "recovery"
        ]

        return cls(
            agent_id=data["id"],
            public_key_multibase=primary_key,
            service_endpoint=endpoint,
            capabilities=data.get("capabilityDeclaration", []),
            trust_attestations=data.get("trustAttestations", []),
            revoked_keys=data.get("revocation", []),
            recovery_keys=recovery,
        )


@dataclass
class AgentIdentity:
    """Manages an agent's complete cryptographic identity.

    Holds the signing keypair, encryption keypair, derived DID, and
    provides methods to produce DID Documents, sign data, and rotate keys.

    Attributes:
        signing_keys: Ed25519 keypair for message signing.
        encryption_keys: X25519 keypair for ECDH key exchange.
        agent_id: The derived OCP DID.
        network: Network identifier.
        created_at: When the identity was generated.
        key_fingerprint: First 16 hex chars of SHA-3-256(public_key).
        previous_keys: List of rotated-out signing keypairs (for graceful rotation).
    """

    signing_keys: SigningKeyPair
    encryption_keys: EncryptionKeyPair
    agent_id: str
    network: str = NETWORK_MAINNET
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    previous_keys: list[SigningKeyPair] = field(default_factory=list, repr=False)

    @classmethod
    def generate(cls, network: str = NETWORK_MAINNET) -> AgentIdentity:
        """Generate a brand-new agent identity.

        Creates fresh Ed25519 and X25519 keypairs, derives the agent DID,
        and initializes the identity.

        Args:
            network: Network identifier (``"mainnet"`` or ``"testnet"``).

        Returns:
            A new :class:`AgentIdentity`.
        """
        signing = SigningKeyPair.generate()
        encryption = EncryptionKeyPair.generate()
        agent_id = derive_agent_id(signing.public_key_bytes, network)
        return cls(
            signing_keys=signing,
            encryption_keys=encryption,
            agent_id=agent_id,
            network=network,
        )

    @classmethod
    def from_private_key(cls, private_key_bytes: bytes, network: str = NETWORK_MAINNET) -> AgentIdentity:
        """Restore an identity from a raw Ed25519 private key.

        Useful after key recovery via Shamir's Secret Sharing.

        Args:
            private_key_bytes: 32-byte Ed25519 private key.
            network: Network identifier.

        Returns:
            The restored :class:`AgentIdentity`.
        """
        signing = SigningKeyPair.from_private_bytes(private_key_bytes)
        encryption = EncryptionKeyPair.generate()
        agent_id = derive_agent_id(signing.public_key_bytes, network)
        return cls(
            signing_keys=signing,
            encryption_keys=encryption,
            agent_id=agent_id,
            network=network,
        )

    @property
    def key_fingerprint(self) -> str:
        """First 16 hex chars of SHA-3-256(public_key).

        Used for recovery share verification.
        """
        return sha3_256_hex(self.signing_keys.public_key_bytes)[:16]

    def did_document(
        self,
        service_endpoint: str,
        capabilities: list[str] | None = None,
        recovery_keys: list[dict[str, Any]] | None = None,
    ) -> DIDDocument:
        """Build a DID Document for this identity.

        Args:
            service_endpoint: The agent's OCP messaging URL.
            capabilities: Optional list of capability identifiers.
            recovery_keys: Optional list of recovery key entries.

        Returns:
            A :class:`DIDDocument` instance.
        """
        return DIDDocument(
            agent_id=self.agent_id,
            public_key_multibase=self.signing_keys.public_key_multibase,
            service_endpoint=service_endpoint,
            capabilities=capabilities or [],
            recovery_keys=recovery_keys or [],
        )

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary data with the current signing key.

        Args:
            data: Bytes to sign.

        Returns:
            64-byte Ed25519 signature.
        """
        return self.signing_keys.sign(data)

    def rotate_signing_key(self) -> SigningKeyPair:
        """Rotate the signing key.

        Moves the current signing key to ``previous_keys`` and generates
        a fresh one. The agent DID does **not** change (it is derived from
        the original key). The old key should be added to the DID Document's
        revocation list after a grace period.

        Returns:
            The **old** :class:`SigningKeyPair` (now in ``previous_keys``).
        """
        old = self.signing_keys
        self.previous_keys.append(old)
        new_signing = SigningKeyPair.generate()
        object.__setattr__(self, "signing_keys", new_signing)
        return old

    def rotate_encryption_key(self) -> EncryptionKeyPair:
        """Rotate the encryption key.

        Generates a fresh X25519 keypair. The old keypair is returned
        so the caller can continue to decrypt in-flight messages.

        Returns:
            The **old** :class:`EncryptionKeyPair`.
        """
        old = self.encryption_keys
        object.__setattr__(self, "encryption_keys", EncryptionKeyPair.generate())
        return old
        