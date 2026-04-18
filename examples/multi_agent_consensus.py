"""Example: Multi-agent consensus on a fraud pattern classification.

This demonstrates:
  1. Configuring a consensus round with quorum and threshold
  2. Casting weighted votes from multiple agents
  3. Resolving the consensus with Byzantine fault tolerance
  4. Inspecting the detailed result

Usage:
    python examples/multi_agent_consensus.py
"""

from datetime import datetime, timedelta, timezone

from ocp.consensus import ConsensusConfig, ConsensusRound, Vote


def main() -> None:
    # ---- Configure the consensus round ----
    config = ConsensusConfig(
        topic="Classify pattern FP-2026-0042 as confirmed fraud indicator",
        options=["confirm", "reject", "needs_more_data"],
        min_participants=5,
        threshold=0.67,
        weighted=True,
        deadline=datetime.now(timezone.utc) + timedelta(hours=24),
        min_trust_level=2,
        required_domains=["finance", "fraud_detection"],
    )

    round = ConsensusRound(config)
    print(f"Consensus round initiated")
    print(f"  ID:           {round.consensus_id}")
    print(f"  Topic:        {config.topic}")
    print(f"  Options:      {config.options}")
    print(f"  Quorum:       {config.min_participants} participants")
    print(f"  Threshold:    {config.threshold * 100:.0f}%")
    print(f"  Weighted:     {config.weighted}")
    print(f"  Deadline:     {config.deadline}")
    print()

    # ---- Show the initiation payload (what would be broadcast) ----
    init_payload = round.initiation_payload()
    print(f"Initiation payload for broadcast:")
    print(f"  consensus_id:     {init_payload['consensus_id']}")
    print(f"  eligible_agents:  min_trust={init_payload['eligible_agents']['min_trust_level']}")
    print(f"                    domains={init_payload['eligible_agents']['required_domains']}")
    print()

    # ---- Cast votes from 7 agents ----
    # Simulating a realistic scenario: 5 experts agree, 1 disagrees, 1 wants more data
    votes = [
        Vote(
            voter_id="did:ocp:mainnet:agent-expert000001",
            option="confirm",
            confidence=0.95,
            trust_score=0.9,
        ),
        Vote(
            voter_id="did:ocp:mainnet:agent-expert000002",
            option="confirm",
            confidence=0.88,
            trust_score=0.8,
        ),
        Vote(
            voter_id="did:ocp:mainnet:agent-expert000003",
            option="confirm",
            confidence=0.72,
            trust_score=0.7,
        ),
        Vote(
            voter_id="did:ocp:mainnet:agent-contrarian01",
            option="reject",
            confidence=0.60,
            trust_score=0.5,
        ),
        Vote(
            voter_id="did:ocp:mainnet:agent-expert000004",
            option="confirm",
            confidence=0.91,
            trust_score=0.85,
        ),
        Vote(
            voter_id="did:ocp:mainnet:agent-cautious0001",
            option="needs_more_data",
            confidence=0.55,
            trust_score=0.6,
        ),
        Vote(
            voter_id="did:ocp:mainnet:agent-expert000005",
            option="confirm",
            confidence=0.80,
            trust_score=0.75,
        ),
    ]

    print("Casting votes:")
    for v in votes:
        accepted = round.cast_vote(v)
        status = "accepted" if accepted else "REJECTED"
        short_id = v.voter_id.split("agent-")[1]
        print(f"  {short_id}: {v.option:18s} "
              f"confidence={v.confidence:.2f}  trust={v.trust_score:.2f}  [{status}]")

    # ---- Demonstrate duplicate rejection ----
    print()
    dup = Vote(
        voter_id="did:ocp:mainnet:agent-expert000001",  # same as first voter
        option="reject",
        confidence=0.99,
        trust_score=0.99,
    )
    dup_accepted = round.cast_vote(dup)
    print(f"Duplicate vote from expert000001: {'accepted' if dup_accepted else 'REJECTED (as expected)'}")

    # ---- Demonstrate invalid option rejection ----
    bad = Vote(
        voter_id="did:ocp:mainnet:agent-newagent00001",
        option="maybe",  # not in options list
        confidence=0.5,
        trust_score=0.5,
    )
    bad_accepted = round.cast_vote(bad)
    print(f"Invalid option 'maybe':           {'accepted' if bad_accepted else 'REJECTED (as expected)'}")
    print()

    # ---- Resolve ----
    result = round.resolve()
    print(f"Consensus result:")
    print(f"  Winner:            {result.winner or 'NO CONSENSUS'}")
    print(f"  Quorum reached:    {result.reached_quorum} ({result.total_votes}/{config.min_participants})")
    print(f"  Threshold reached: {result.reached_threshold}")
    print(f"  Total votes:       {result.total_votes}")
    print()
    print(f"  Weighted scores:")
    for option, score in sorted(result.weighted_scores.items(), key=lambda x: -x[1]):
        total = sum(result.weighted_scores.values())
        pct = (score / total * 100) if total > 0 else 0
        bar = "#" * int(pct / 2)
        print(f"    {option:18s} {score:6.3f}  ({pct:5.1f}%)  {bar}")
    print()

    # ---- Show the result payload (what would be broadcast) ----
    result_payload = round.result_payload(result)
    print(f"Result payload for broadcast:")
    print(f"  consensus_id:      {result_payload['consensus_id']}")
    print(f"  winner:            {result_payload['winner']}")
    print(f"  reached_quorum:    {result_payload['reached_quorum']}")
    print(f"  reached_threshold: {result_payload['reached_threshold']}")


if __name__ == "__main__":
    main()


═══ FILE: examples/key_recovery.py ═══

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

from ocp.identity import AgentIdentity
from ocp.recovery import RecoveryManager
from ocp.crypto import EncryptionKeyPair, sha3_256_hex


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

