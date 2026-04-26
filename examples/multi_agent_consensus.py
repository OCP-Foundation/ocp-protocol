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