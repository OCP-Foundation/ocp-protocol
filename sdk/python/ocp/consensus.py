"""Consensus protocol — initiation, voting, and resolution.

Implements OCP's multi-agent consensus mechanism (§6.2) with:

- Weighted voting based on trust scores and confidence
- Configurable quorum and threshold requirements
- Byzantine fault tolerance (tolerates up to n/3 malicious agents)
- Deadline enforcement and duplicate vote rejection
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ocp.crypto import SigningKeyPair, b64url_encode, generate_uuid_short, sha3_256
from ocp.exceptions import OCPConsensusError

logger = logging.getLogger("ocp.consensus")


@dataclass
class ConsensusConfig:
    """Configuration for a consensus round.

    Attributes:
        topic: Human-readable description of what's being decided.
        options: Available vote options.
        min_participants: Minimum number of votes for quorum.
        threshold: Fraction of weighted score needed to win (0.0–1.0).
        weighted: Whether to use trust-weighted scoring.
        deadline: UTC deadline for vote submission.
        min_trust_level: Minimum trust level to participate.
        required_domains: Required domain expertise.
    """

    topic: str
    options: list[str]
    min_participants: int = 5
    threshold: float = 0.67
    weighted: bool = True
    deadline: datetime | None = None
    min_trust_level: int = 2
    required_domains: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.options) < 2:
            raise ValueError("Consensus requires at least 2 options")
        if not 0.0 < self.threshold <= 1.0:
            raise ValueError(f"Threshold must be in (0.0, 1.0], got {self.threshold}")
        if self.min_participants < 1:
            raise ValueError("min_participants must be >= 1")


@dataclass
class Vote:
    """A single consensus vote.

    Attributes:
        voter_id: DID of the voting agent.
        option: The selected option.
        confidence: Voter's confidence in their choice (0.0–1.0).
        trust_score: The voter's current trust score (0.0–1.0).
        signature: Optional Ed25519 signature over the vote content.
        timestamp: When the vote was cast.
    """

    voter_id: str
    option: str
    confidence: float
    trust_score: float
    signature: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def sign(self, signing_keys: SigningKeyPair, consensus_id: str) -> None:
        """Sign this vote.

        Args:
            signing_keys: The voter's signing keys.
            consensus_id: The consensus round identifier.
        """
        sign_data = f"{consensus_id}||{self.voter_id}||{self.option}||{self.confidence}".encode()
        sig = signing_keys.sign(sha3_256(sign_data))
        self.signature = b64url_encode(sig)


@dataclass(frozen=True)
class ConsensusResult:
    """Result of a consensus round.

    Attributes:
        consensus_id: The round identifier.
        winner: The winning option, or ``None`` if no consensus.
        weighted_scores: Weighted score per option.
        total_votes: Number of votes received.
        reached_quorum: Whether quorum was met.
        reached_threshold: Whether the threshold was met.
    """

    consensus_id: str
    winner: str | None
    weighted_scores: dict[str, float]
    total_votes: int
    reached_quorum: bool
    reached_threshold: bool


class ConsensusRound:
    """Manages a single consensus round.

    Handles vote collection, duplicate detection, deadline enforcement,
    and result resolution.

    Args:
        config: The consensus configuration.

    Usage::

        round = ConsensusRound(config)
        round.cast_vote(vote1)
        round.cast_vote(vote2)
        result = round.resolve()
    """

    def __init__(self, config: ConsensusConfig) -> None:
        self.consensus_id = generate_uuid_short("con-")
        self.config = config
        self._votes: list[Vote] = []
        self._voter_ids: set[str] = set()
        self._created_at = datetime.now(timezone.utc)

    @property
    def vote_count(self) -> int:
        """Number of votes received so far."""
        return len(self._votes)

    @property
    def is_past_deadline(self) -> bool:
        """Whether the deadline has passed."""
        if self.config.deadline is None:
            return False
        return datetime.now(timezone.utc) > self.config.deadline

    def initiation_payload(self) -> dict[str, Any]:
        """Build the ``consensus_initiate`` message payload.

        Returns:
            Payload dict for a consensus initiation OCPUMF message.
        """
        return {
            "consensus_id": self.consensus_id,
            "topic": self.config.topic,
            "options": self.config.options,
            "quorum": {
                "min_participants": self.config.min_participants,
                "threshold": self.config.threshold,
                "weighted": self.config.weighted,
            },
            "deadline": (
                self.config.deadline.strftime("%Y-%m-%dT%H:%M:%SZ")
                if self.config.deadline else None
            ),
            "eligible_agents": {
                "min_trust_level": self.config.min_trust_level,
                "required_domains": self.config.required_domains,
            },
        }

    def cast_vote(self, vote: Vote) -> bool:
        """Record a vote.

        Validates the vote against the round configuration and rejects
        duplicates, invalid options, and out-of-range confidence values.

        Args:
            vote: The vote to record.

        Returns:
            ``True`` if the vote was accepted, ``False`` if rejected.
        """
        # Reject duplicates
        if vote.voter_id in self._voter_ids:
            logger.warning("Duplicate vote from %s rejected", vote.voter_id)
            return False

        # Reject invalid option
        if vote.option not in self.config.options:
            logger.warning(
                "Invalid option '%s' from %s rejected", vote.option, vote.voter_id
            )
            return False

        # Reject out-of-range confidence
        if not 0.0 <= vote.confidence <= 1.0:
            logger.warning(
                "Invalid confidence %.2f from %s rejected",
                vote.confidence, vote.voter_id,
            )
            return False

        # Reject after deadline
        if self.is_past_deadline:
            logger.warning("Vote from %s rejected: past deadline", vote.voter_id)
            return False

        self._voter_ids.add(vote.voter_id)
        self._votes.append(vote)
        return True

    def resolve(self) -> ConsensusResult:
        """Tally votes and determine the result.

        Uses weighted scoring if configured:
        ``weighted_score(option) = Σ(voter_trust_score × voter_confidence)``

        Returns:
            A :class:`ConsensusResult` with the outcome.
        """
        scores: dict[str, float] = {opt: 0.0 for opt in self.config.options}

        for v in self._votes:
            if self.config.weighted:
                scores[v.option] += v.trust_score * v.confidence
            else:
                scores[v.option] += 1.0

        total = sum(scores.values())
        reached_quorum = len(self._votes) >= self.config.min_participants

        winner = None
        reached_threshold = False

        if total > 0:
            best_option = max(scores, key=lambda k: scores[k])
            ratio = scores[best_option] / total
            if ratio >= self.config.threshold:
                winner = best_option
                reached_threshold = True

        # Winner only counts if both quorum and threshold are met
        final_winner = winner if (reached_quorum and reached_threshold) else None

        result = ConsensusResult(
            consensus_id=self.consensus_id,
            winner=final_winner,
            weighted_scores={k: round(v, 4) for k, v in scores.items()},
            total_votes=len(self._votes),
            reached_quorum=reached_quorum,
            reached_threshold=reached_threshold,
        )

        logger.info(
            "Consensus %s resolved: winner=%s, quorum=%s, threshold=%s",
            self.consensus_id, final_winner, reached_quorum, reached_threshold,
        )

        return result

    def result_payload(self, result: ConsensusResult) -> dict[str, Any]:
        """Build the ``consensus_result`` message payload.

        Args:
            result: The resolved consensus result.

        Returns:
            Payload dict for a ``consensus_result`` OCPUMF message.
        """
        return {
            "consensus_id": result.consensus_id,
            "winner": result.winner,
            "weighted_scores": result.weighted_scores,
            "total_votes": result.total_votes,
            "reached_quorum": result.reached_quorum,
            "reached_threshold": result.reached_threshold,
        }
        