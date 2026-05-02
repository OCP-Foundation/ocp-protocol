"""Example: Share knowledge between two bonded agents.

This demonstrates the full knowledge sharing workflow:
  1. Create two agents (Alice and Bob)
  2. Establish a bond with scoped permissions
  3. Create an insight package
  4. Validate it against the Privacy Validation Layer
  5. Share it (would send via transport in production)

Usage:
    python examples/knowledge_sharing.py
"""

import asyncio

from ocp.agent import Agent
from ocp.knowledge import InsightPackage, InsightFeature, EmbeddingPackage, EmbeddingVector
from ocp.pvl import validate_knowledge_payload
from ocp.trust import Bond, BondPermissions


async def main() -> None:
    # ---- Create two agents ----
    alice = Agent(
        name="AliceFinanceAI",
        capabilities=["nlp:classification", "finance:fraud_detection"],
        domains=["finance", "fraud_detection"],
    )
    bob = Agent(
        name="BobRiskAI",
        capabilities=["finance:risk_analysis"],
        domains=["finance", "risk_analysis"],
    )

    print(f"Alice: {alice.agent_id}")
    print(f"Bob:   {bob.agent_id}")
    print()

    # ---- Establish a bond ----
    # In production, this goes through the bond_request/bond_accept protocol.
    # Here we create it directly to demonstrate permission scoping.
    bond = Bond(
        agent_a=alice.agent_id,
        agent_b=bob.agent_id,
        permissions=BondPermissions(
            knowledge_share=True,
            knowledge_allowed_types=["insight", "embedding"],
            max_payload_bytes=10_485_760,
            task_delegate=True,
            max_concurrent_tasks=3,
            model_delta_share=False,  # Alice and Bob don't share model weights
        ),
    )
    alice.accept_bond(bob.agent_id, bond)

    print(f"Bond established: {bond.bond_id}")
    print(f"  Knowledge share: {bond.permits_knowledge_share('insight')}")
    print(f"  Model deltas:    {bond.permits_model_delta()}")
    print(f"  Task delegation: {bond.permits_task_delegation()}")
    print(f"  Active:          {bond.is_active}")
    print()

    # ---- Create an insight ----
    insight = InsightPackage(
        topic="credit_risk_pattern",
        description="Micro-transaction velocity anomaly preceding large transfers. "
                    "Pattern detected across anonymized transaction logs showing "
                    "burst activity of 40+ small transactions in a 5-minute window "
                    "followed by a single large transfer exceeding 100x the mean.",
        confidence=0.91,
        source_agent=alice.agent_id,
        derived_from="anonymized_transaction_logs",
        methodology="unsupervised_clustering",
        category="anomaly_detection",
        evidence_count=14203,
        features=[
            InsightFeature(
                name="tx_velocity_5min",
                type="float",
                threshold=42.0,
                direction="above",
            ),
            InsightFeature(
                name="amount_ratio_large_to_mean",
                type="float",
                threshold=100.0,
                direction="above",
            ),
        ],
        recommended_action="flag_for_review",
        false_positive_rate=0.03,
    )

    payload = insight.to_payload()
    print(f"Insight created: {payload['insight_id']}")
    print(f"  Topic:      {payload['topic']}")
    print(f"  Confidence: {payload['confidence']}")
    print(f"  Evidence:   {payload['evidence_count']} samples")
    print(f"  Anonymized: {payload['anonymized']}")
    print(f"  Features:   {len(payload['payload']['features'])}")
    print(f"  Provenance: {payload['provenance']['source_agent']}")
    if 'reproducibility_hash' in payload['provenance']:
        print(f"  Repro hash: {payload['provenance']['reproducibility_hash'][:24]}...")
    print()

    # ---- PVL validation ----
    result = validate_knowledge_payload(payload)
    print(f"PVL validation: {'PASSED' if result.passed else 'FAILED'}")
    if not result.passed:
        print(f"  Code:   {result.rejection_code}")
        print(f"  Reason: {result.rejection_reason}")
    print()

    # ---- Demonstrate PVL rejection (PII) ----
    print("Testing PVL with injected PII...")
    bad_payload = payload.copy()
    bad_payload = {**payload}
    bad_payload["payload"] = {**payload["payload"]}
    bad_payload["payload"]["description"] = "Contact john.doe@example.com for details"
    bad_result = validate_knowledge_payload(bad_payload)
    print(f"  PVL result: {'PASSED' if bad_result.passed else 'REJECTED'}")
    print(f"  Code:       {bad_result.rejection_code}")
    print(f"  Reason:     {bad_result.rejection_reason}")
    print()

    # ---- Create an embedding package ----
    embedding = EmbeddingPackage(
        dimensions=4,
        vectors=[
            EmbeddingVector.from_floats(
                label="fraud_pattern_centroid",
                values=[0.82, -0.15, 0.47, 0.91],
                source_domain="finance",
            ),
            EmbeddingVector.from_floats(
                label="normal_pattern_centroid",
                values=[0.11, 0.63, -0.22, 0.08],
                source_domain="finance",
            ),
        ],
    )
    emb_payload = embedding.to_payload()
    emb_result = validate_knowledge_payload(emb_payload)
    print(f"Embedding package: {len(emb_payload['vectors'])} vectors, {emb_payload['dimensions']}D")
    print(f"  PVL: {'PASSED' if emb_result.passed else 'FAILED'}")
    print()

    # ---- Bond permission check ----
    print("Bond permission checks:")
    print(f"  Share insight?      {bond.permits_knowledge_share('insight')}")
    print(f"  Share embedding?    {bond.permits_knowledge_share('embedding')}")
    print(f"  Share model delta?  {bond.permits_knowledge_share('model_delta')}")
    print()

    # In production, this would send via transport:
    # await alice.share(insight, to=bob.agent_id)
    print("Knowledge ready to share. In production, call:")
    print("  await alice.share(insight, to=bob.agent_id)")

    await alice.close()
    await bob.close()
    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
