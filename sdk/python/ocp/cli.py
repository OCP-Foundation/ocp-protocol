"""Command-line utilities for OCP.

Provides:
- ``ocp-keygen``: Generate a new agent identity and print the DID and keys.
"""

from __future__ import annotations

import json
import base64
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from ocp.identity import AgentIdentity

def keygen() -> None:
    """Generate a new OCP agent identity and output details."""
    parser = argparse.ArgumentParser(description="Generate an OCP agent identity")
    parser.add_argument(
        "--network", default="mainnet", choices=["mainnet", "testnet"],
        help="Network identifier (default: mainnet)",
    )
    parser.add_argument(
        "--endpoint", default="",
        help="Service endpoint URL",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output to stdout as JSON",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (e.g., identity.json)",
    )

    args = parser.parse_args()

    # Generate the identity
    identity = AgentIdentity.generate(network=args.network)

    def to_b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    # Extract Signing Keys (Ed25519)
    sig_priv = identity.signing_keys.private_key_bytes

    # Extract Encryption Keys (X25519)
    enc_key_object = identity.encryption_keys.private_key
    enc_priv = enc_key_object.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    output_data = {
        "agent_id": identity.agent_id,
        "network": identity.network,
        "public_key": identity.signing_keys.public_key_b64url,
        "private_key": to_b64url(sig_priv),
        "key_fingerprint": identity.key_fingerprint,
        "encryption_public_key": identity.encryption_keys.public_key_b64url,
        "encryption_private_key": to_b64url(enc_priv),
    }

    if args.endpoint:
        output_data["did_document"] = identity.did_document(args.endpoint).to_dict()

    # Handle File Output
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        print(f"✅ Identity successfully saved to: {args.output}")

    # Handle Stdout Display
    if args.json:
        print(json.dumps(output_data, indent=2))
    elif not args.output:
        print(f"Agent ID:          {identity.agent_id}")
        print(f"Network:           {identity.network}")
        print(f"Public Key:        {identity.signing_keys.public_key_b64url}")
        print(f"Key Fingerprint:   {identity.key_fingerprint}")
        print(f"Encryption Key:    {identity.encryption_keys.public_key_b64url}")

if __name__ == "__main__":
    keygen()
