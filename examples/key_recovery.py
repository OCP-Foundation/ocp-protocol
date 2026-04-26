"""Example: Full key recovery lifecycle.

This demonstrates:
  1. Agent identity generation
  2. Recovery share generation (3-of-5 Shamir)
  3. Encrypted share distribution to custodians
  4. Simulated key loss
  5. Recovery from 3 custodians
  6. Verification that the recovered key matches
  7. Post-recovery key rotation

Usage:
    python examples/key_recovery.py
"""

from ocp.crypto import EncryptionKeyPair, sha3_256_hex
from ocp.identity import AgentIdentity
from ocp.recovery import RecoveryManager


def main() -> None:
    # ---- Step 1: Generate agent identity ----
    print("=" * 60)
    print("Step 1: Generate agent identity")
    print("=" * 60)
    agent = AgentIdentity.generate(network="mainnet")
    print(f"  Agent ID:      {agent.agent_id}")
    print(f"  Network:       {agent.network}")
    print(f"  Fingerprint:   {agent.key_fingerprint}")
    print(f"  Public key:    {agent.signing_keys.public_key_b64url[:32]}...")
    print()

    # ---- Step 2: Generate recovery shares ----
    print("=" * 60)
    print("Step 2: Generate recovery shares (3-of-5)")
    print("=" * 60)
    mgr = RecoveryManager(agent.agent_id, agent.signing_keys)
    shares = mgr.generate_shares(threshold=3, num_shares=5)

    for s in shares:
        d = s.to_dict()
        print(f"  {d['share_id']}")
        print(f"    Index:   {d['share_index']}")
        print(f"    Scheme:  {d['scheme']}")
        print(f"    Expires: {d['expires_at']}")
    print()

    # ---- Step 3: Encrypt shares for custodians ----
    print("=" * 60)
    print("Step 3: Encrypt shares for 5 custodians")
    print("=" * 60)
    custodians = []
    for i, share in enumerate(shares):
        custodian_keys = EncryptionKeyPair.generate()
        encrypted = mgr.encrypt_share_for_custodian(share, custodian_keys.public_key_bytes)
        custodians.append({
            "index": share.share_index,
            "keys": custodian_keys,
            "encrypted": encrypted,
        })
        print(f"  Custodian {i + 1}: share {share.share_index} encrypted")
        print(f"    Ephemeral key: {encrypted['ephemeral_public_key'][:24]}...")
        print(f"    Nonce:         {encrypted['nonce'][:16]}...")
    print()

    # ---- Step 4: Simulate key loss ----
    print("=" * 60)
    print("Step 4: KEY LOST — agent needs recovery")
    print("=" * 60)
    print(f"  Agent ID to recover: {agent.agent_id}")
    print(f"  Key fingerprint:     {mgr.key_fingerprint}")
    print(f"  Contacting custodians 1, 3, and 5...")
    print()

    # ---- Step 5: Recover from 3 custodians ----
    print("=" * 60)
    print("Step 5: Collect and decrypt shares from custodians 1, 3, 5")
    print("=" * 60)
    selected = [custodians[0], custodians[2], custodians[4]]
    collected_shares = []

    for c in selected:
        decrypted = RecoveryManager.decrypt_share(c["encrypted"], c["keys"].private_key)
        collected_shares.append((c["index"], decrypted))
        print(f"  Custodian (share {c['index']}): decrypted successfully")

    print()
    recovered_key = RecoveryManager.reconstruct(collected_shares, mgr.key_fingerprint)
    print(f"  Private key recovered: {len(recovered_key)} bytes")
    print(f"  Fingerprint verified:  {mgr.key_fingerprint}")
    print()

    # ---- Step 6: Verify recovered key ----
    print("=" * 60)
    print("Step 6: Verify recovered key works")
    print("=" * 60)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = Ed25519PrivateKey.from_private_bytes(recovered_key)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fp = sha3_256_hex(pub_bytes)[:16]

    print(f"  Derived fingerprint: {fp}")
    print(f"  Expected:            {mgr.key_fingerprint}")
    print(f"  Match:               {fp == mgr.key_fingerprint}")

    # Sign something with the recovered key
    test_data = b"Recovery verification message"
    signature = priv.sign(test_data)
    priv.public_key().verify(signature, test_data)
    print(f"  Signature verified with recovered key")
    print()

    # ---- Step 7: Restore identity and verify agent ID ----
    print("=" * 60)
    print("Step 7: Restore agent identity")
    print("=" * 60)
    restored = AgentIdentity.from_private_key(recovered_key, network="mainnet")
    print(f"  Original agent ID:  {agent.agent_id}")
    print(f"  Restored agent ID:  {restored.agent_id}")
    print(f"  Match:              {agent.agent_id == restored.agent_id}")
    print()

    # ---- Step 8: Post-recovery key rotation ----
    print("=" * 60)
    print("Step 8: Post-recovery key rotation (mandatory per spec)")
    print("=" * 60)
    old_fp = restored.key_fingerprint
    old_key = restored.rotate_signing_key()
    new_fp = restored.key_fingerprint

    print(f"  Old fingerprint: {old_fp}")
    print(f"  New fingerprint: {new_fp}")
    print(f"  Agent ID stable: {restored.agent_id == agent.agent_id}")
    print(f"  Old key archived: {old_key in restored.previous_keys}")
    print()

    print("=" * 60)
    print("Recovery complete")
    print("=" * 60)
    print()
    print("Summary:")
    print("  - No master key was used")
    print("  - No backdoor was exploited")
    print("  - 3 independent custodians cooperated")
    print("  - The private key was reconstructed via Lagrange interpolation")
    print("  - The agent ID survived the entire process")
    print("  - A new key was generated and the old one archived")
    print("  - In production: revoke old shares, distribute new ones")


if __name__ == "__main__":
    main()