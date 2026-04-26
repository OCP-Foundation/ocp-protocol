"""Tests for the consensus protocol.

Compliance category: Consensus Protocol (6 tests)
"""

from datetime import datetime, timedelta, timezone

import pytest

from ocp.consensus import ConsensusConfig, ConsensusRound, Vote


class TestConsensusRound:
    """OCP-SPEC §6.2 — Consensus protocol."""

    def _make_round(self, **kwargs) -> ConsensusRound:
        defaults = {
            "topic": "Classify pattern FP-2026-0042",
            "options": ["confirm", "reject", "abstain"],
            "min_participants": 3,
            "threshold": 0.67,
            "weighted": True,
        }
        defaults.update(kwargs)
        return ConsensusRound(ConsensusConfig(**defaults))

    def test_basic_consensus_reached(self):
        r = self._make_round()
        r.cast_vote(Vote(voter_id="a", option="confirm", confidence=0.9, trust_score=0.8))
        r.cast_vote(Vote(voter_id="b", option="confirm", confidence=0.85, trust_score=0.7))
        r.cast_vote(Vote(voter_id="c", option="reject", confidence=0.5, trust_score=0.3))
        result = r.resolve()
        assert result.winner == "confirm"
        assert result.reached_quorum
        assert result.reached_threshold
        assert result.total_votes == 3

    def test_no_quorum(self):
        r = self._make_round(min_participants=5)
        r.cast_vote(Vote(voter_id="a", option="confirm", confidence=0.9, trust_score=0.8))
        r.cast_vote(Vote(voter_id="b", option="confirm", confidence=0.85, trust_score=0.7))
        result = r.resolve()
        assert result.winner is None
        assert not result.reached_quorum

    def test_no_threshold(self):
        r = self._make_round(threshold=0.95)
        r.cast_vote(Vote(voter_id="a", option="confirm", confidence=0.9, trust_score=0.5))
        r.cast_vote(Vote(voter_id="b", option="reject", confidence=0.8, trust_score=0.5))
        r.cast_vote(Vote(voter_id="c", option="abstain", confidence=0.7, trust_score=0.5))
        result = r.resolve()
        assert result.winner is None
        assert not result.reached_threshold

    def test_duplicate_vote_rejected(self):
        r = self._make_round()
        assert r.cast_vote(Vote(voter_id="a", option="confirm", confidence=0.9, trust_score=0.8))
        assert not r.cast_vote(Vote(voter_id="a", option="reject", confidence=0.5, trust_score=0.8))
        assert r.vote_count == 1

    def test_invalid_option_rejected(self):
        r = self._make_round()
        assert not r.cast_vote(Vote(voter_id="a", option="maybe", confidence=0.5, trust_score=0.5))

    def test_invalid_confidence_rejected(self):
        r = self._make_round()
        assert not r.cast_vote(Vote(voter_id="a", option="confirm", confidence=1.5, trust_score=0.5))
        assert not r.cast_vote(Vote(voter_id="b", option="confirm", confidence=-0.1, trust_score=0.5))

    def test_unweighted_consensus(self):
        r = self._make_round(weighted=False)
        # Total of 6 voters to clear the quorum of 5
        # 4 'confirm' vs 2 'reject' = 66.6% (Still might fail 0.67!)
        # Let's do 5 'confirm' vs 1 'reject' = 83.3%
        r.cast_vote(Vote(voter_id="a", option="confirm", confidence=0.1, trust_score=0.1))
        r.cast_vote(Vote(voter_id="b", option="confirm", confidence=0.1, trust_score=0.1))
        r.cast_vote(Vote(voter_id="d", option="confirm", confidence=0.1, trust_score=0.1))
        r.cast_vote(Vote(voter_id="e", option="confirm", confidence=0.1, trust_score=0.1))
        r.cast_vote(Vote(voter_id="f", option="confirm", confidence=0.1, trust_score=0.1))

        r.cast_vote(Vote(voter_id="c", option="reject", confidence=0.99, trust_score=0.99))

        result = r.resolve()

        # 5/6 = 83.3%, which safely clears the 0.67 threshold
        # Total votes = 6, which safely clears the quorum of 5
        assert result.winner == "confirm"

    def test_bft_with_30_percent_malicious(self):
        """Byzantine fault tolerance: consensus holds with <33% malicious."""
        r = self._make_round(min_participants=10, threshold=0.51)
        # 7 honest agents vote confirm
        for i in range(7):
            r.cast_vote(Vote(voter_id=f"honest-{i}", option="confirm", confidence=0.8, trust_score=0.7))
        # 3 malicious agents vote reject with max scores
        for i in range(3):
            r.cast_vote(Vote(voter_id=f"bad-{i}", option="reject", confidence=1.0, trust_score=1.0))
        result = r.resolve()
        assert result.winner == "confirm"
        assert result.reached_quorum

    def test_bft_fails_at_35_percent(self):
        """Consensus should fail with >33% malicious high-trust agents."""
        r = self._make_round(min_participants=10, threshold=0.67, options=["confirm", "reject"])
        # 13 honest agents
        for i in range(13):
            r.cast_vote(Vote(voter_id=f"honest-{i}", option="confirm", confidence=0.7, trust_score=0.5))
        # 7 malicious agents (35%) with max trust
        for i in range(7):
            r.cast_vote(Vote(voter_id=f"bad-{i}", option="reject", confidence=1.0, trust_score=1.0))
        result = r.resolve()
        # High-trust adversaries overwhelm honest majority
        assert result.winner != "confirm" or not result.reached_threshold

    def test_deadline_enforcement(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        r = self._make_round(deadline=past)
        assert r.is_past_deadline
        assert not r.cast_vote(Vote(voter_id="a", option="confirm", confidence=0.9, trust_score=0.8))

    def test_initiation_payload(self):
        r = self._make_round(required_domains=["finance"])
        payload = r.initiation_payload()
        assert payload["consensus_id"].startswith("con-")
        assert payload["topic"] == "Classify pattern FP-2026-0042"
        assert payload["options"] == ["confirm", "reject", "abstain"]
        assert payload["quorum"]["threshold"] == 0.67

    def test_result_payload(self):
        r = self._make_round()
        r.cast_vote(Vote(voter_id="a", option="confirm", confidence=0.9, trust_score=0.8))
        r.cast_vote(Vote(voter_id="b", option="confirm", confidence=0.8, trust_score=0.7))
        r.cast_vote(Vote(voter_id="c", option="reject", confidence=0.5, trust_score=0.3))
        result = r.resolve()
        payload = r.result_payload(result)
        assert payload["consensus_id"] == r.consensus_id
        assert payload["winner"] == "confirm"
        assert payload["total_votes"] == 3

    def test_config_validation(self):
        with pytest.raises(ValueError, match="at least 2"):
            ConsensusConfig(topic="t", options=["only_one"])
        with pytest.raises(ValueError, match="threshold"):
            ConsensusConfig(topic="t", options=["a", "b"], threshold=0.0)

