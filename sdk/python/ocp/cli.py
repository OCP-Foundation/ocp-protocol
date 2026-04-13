"""Command-line utilities for OCP.

Provides:
- ``ocp-keygen``: Generate a new agent identity and print the DID and keys.
"""

from __future__ import annotations

import json
import sys

from ocp.identity import AgentIdentity


def keygen() -> None:
    """Generate a new OCP agent identity and print details to stdout."""
    import argparse

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
        help="Output as JSON",
    )
    args = parser.parse_args()

    identity = AgentIdentity.generate(network=args.network)

    if args.json:
        output = {
            "agent_id": identity.agent_id,
            "network": identity.network,
            "public_key": identity.signing_keys.public_key_b64url,
            "key_fingerprint": identity.key_fingerprint,
            "encryption_public_key": identity.encryption_keys.public_key_b64url,
        }
        if args.endpoint:
            output["did_document"] = identity.did_document(args.endpoint).to_dict()
        print(json.dumps(output, indent=2))
    else:
        print(f"Agent ID:          {identity.agent_id}")
        print(f"Network:           {identity.network}")
        print(f"Public Key:        {identity.signing_keys.public_key_b64url}")
        print(f"Key Fingerprint:   {identity.key_fingerprint}")
        print(f"Encryption Key:    {identity.encryption_keys.public_key_b64url}")
        if args.endpoint:
            print(f"Endpoint:          {args.endpoint}")
            print()
            print("DID Document:")
            doc = identity.did_document(args.endpoint)
            print(json.dumps(doc.to_dict(), indent=2))


if __name__ == "__main__":
    keygen()
