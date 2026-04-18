"""Tests for trust levels, vouching, bonds, and trust score computation.

Compliance category: Trust & Bonding (8 tests)
"""

from datetime import datetime, timedelta, timezone

import pytest

from ocp.trust import (
    Bond,
    BondPermissions,
    TrustLevel,
    TrustScoreWeights,
    Vouch,
    compute_trust_score,
    determine_trust_level,
)


class TestTrustLevels:
    """OCP-SPEC §4.2.1 — Trust level definitions."""

    def test_ordering(self):
        assert TrustLevel.ANONYMOUS < TrustLevel.IDENTIFIED
        assert TrustLevel.IDENTIFIED < TrustLevel.VOUCHED
        assert TrustLevel.VOUCHED < TrustLevel.BONDED
        assert TrustLevel.BONDED < TrustLevel.CERTIFIED

    def test_values(self):
        assert int(TrustLevel.ANONYMOUS) == 0
        assert int(TrustLevel.CERTIFIED) == 4

    def test_determine_anonymous(self):
        assert determine_trust_level(False, 0, 0) == TrustLevel.ANONYMOUS

    def test_determine_identified(self):
        assert determine_trust_level(True, 0, 0) == TrustLevel.IDENTIFIED

    def test_determine_vouched(self):
        assert determine_trust_level(True, 3, 0) == TrustLevel.VOUCHED

    def test_determine_bonded(self):
        assert determine_trust_level(True, 3, 1) == TrustLevel.BONDED

    def test_determine_certified(self):
        assert determine_trust_level(True, 10, 5, is_certified=True) == TrustLevel.CERTIFIED


class TestVouch:
    """OCP-SPEC §4.2.3 — Vouch rules."""

    def test_valid_vouch(self, identity, peer_identity):
        v = Vouch(
            attester_id=identity.agent_id,
            subject_id=peer_identity.agent_id,
            domains=["research"],
        )
        assert v.is_valid
        assert not v.is_expired

    def test_self_vouch_prohibited(self, identity):
        with pytest.raises(ValueError, match="Self-vouching"):
            Vouch(attester_id=identity.agent_id, subject_id=identity.agent_id, domains=["test"])

    def test_max_duration_exceeded(self, identity, peer_identity):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError, match="365"):
            Vouch(
                attester_id=identity.agent_id,
                subject_id=peer_identity.agent_id,
                domains=["test"],
                issued_at=now,
                expires_at=now + timedelta(days=400),
            )

    def test_signed_vouch(self, sample_vouch):
        d = sample_vouch.to_dict()
        assert "signature" in d
        assert len(d["signature"]) > 0

    def test_revocation(self, sample_vouch):
        assert sample_vouch.is_valid
        sample_vouch.revoke()
        assert not sample_vouch.is_valid
        assert sample_vouch.revoked


class TestBondPermissions:
    """OCP-SPEC §4.3.2 — Bond permission scoping."""

    def test_default_permissions(self):
        perms = BondPermissions()
        assert perms.knowledge_share is True
        assert perms.task_delegate is True
        assert perms.model_delta_share is False
        assert "insight" in perms.knowledge_allowed_types
        assert "embedding" in perms.knowledge_allowed_types

    def test_intersection(self):
        p1 = BondPermissions(
            knowledge_share=True,
            knowledge_allowed_types=["insight", "embedding", "model_delta"],
            task_delegate=True,
            max_concurrent_tasks=10,
            model_delta_share=True,
        )
        p2 = BondPermissions(
            knowledge_share=True,
            knowledge_allowed_types=["insight"],
            task_delegate=False,
            max_concurrent_tasks=3,
            model_delta_share=False,
        )
        result = p1.intersect(p2)
        assert result.knowledge_share is True
        assert result.knowledge_allowed_types == ["insight"]
        assert result.task_delegate is False
        assert result.max_concurrent_tasks == 3
        assert result.model_delta_share is False

    def test_serialization_roundtrip(self):
        perms = BondPermissions(knowledge_share=True, task_delegate=False, model_delta_share=True)
        d = perms.to_dict()
        restored = BondPermissions.from_dict(d)
        assert restored.knowledge_share == perms.knowledge_share
        assert restored.task_delegate == perms.task_delegate
        assert restored.model_delta_share == perms.model_delta_share


class TestBond:
    """OCP-SPEC §4.3 — Bond lifecycle."""

    def test_bond_creation(self, sample_bond):
        d = sample_bond.to_dict()
        assert d["bond_id"].startswith("bond-")
        assert len(d["agents"]) == 2
        assert sample_bond.is_active

    def test_max_duration_exceeded(self, identity, peer_identity):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError, match="365"):
            Bond(
                agent_a=identity.agent_id,
                agent_b=peer_identity.agent_id,
                established_at=now,
                expires_at=now + timedelta(days=400),
            )

    def test_knowledge_permission_check(self, sample_bond):
        assert sample_bond.permits_knowledge_share("insight")
        assert sample_bond.permits_knowledge_share("embedding")
        assert not sample_bond.permits_knowledge_share("model_delta")

    def test_task_permission_check(self, sample_bond):
        assert sample_bond.permits_task_delegation()

    def test_model_delta_permission_check(self, sample_bond):
        assert not sample_bond.permits_model_delta()

    def test_revocation(self, sample_bond, identity):
        assert sample_bond.is_active
        sample_bond.revoke(identity.agent_id)
        assert not sample_bond.is_active
        assert sample_bond.revoked_by == identity.agent_id
        assert not sample_bond.permits_knowledge_share("insight")

    def test_involves(self, sample_bond, identity, peer_identity, third_identity):
        assert sample_bond.involves(identity.agent_id)
        assert sample_bond.involves(peer_identity.agent_id)
        assert not sample_bond.involves(third_identity.agent_id)

    def test_peer_of(self, sample_bond, identity, peer_identity):
        assert sample_bond.peer_of(identity.agent_id) == peer_identity.agent_id
        assert sample_bond.peer_of(peer_identity.agent_id) == identity.agent_id
        with pytest.raises(ValueError):
            sample_bond.peer_of("did:ocp:testnet:agent-000000000000")


class TestTrustScore:
    """OCP-SPEC §4.2.2 — Trust score computation."""

    def test_perfect_score(self):
        score = compute_trust_score(
            is_verified=True, vouch_count=10, bond_count=5,
            interaction_reputation=1.0, uptime_ratio=1.0,
        )
        assert score == 1.0

    def test_zero_score(self):
        score = compute_trust_score(
            is_verified=False, vouch_count=0, bond_count=0,
            interaction_reputation=0.0, uptime_ratio=0.0,
        )
        assert score == 0.0

    def test_vouch_cap(self):
        score_10 = compute_trust_score(True, 10, 0, 0.5, 0.5)
        score_100 = compute_trust_score(True, 100, 0, 0.5, 0.5)
        assert score_10 == score_100  # cap at 10

    def test_bond_cap(self):
        score_5 = compute_trust_score(True, 5, 5, 0.5, 0.5)
        score_50 = compute_trust_score(True, 5, 50, 0.5, 0.5)
        assert score_5 == score_50  # cap at 5

    def test_score_in_range(self):
        for _ in range(100):
            import random
            score = compute_trust_score(
                is_verified=random.choice([True, False]),
                vouch_count=random.randint(0, 20),
                bond_count=random.randint(0, 10),
                interaction_reputation=random.random(),
                uptime_ratio=random.random(),
            )
            assert 0.0 <= score <= 1.0

    def test_weights_must_sum_to_one(self):
        with pytest.raises(ValueError, match="sum to 1.0"):
            TrustScoreWeights(
                identity_verification=0.5,
                vouch_count=0.5,
                bond_count=0.5,
                interaction_reputation=0.5,
                uptime_ratio=0.5,
            )

    def test_custom_weights(self):
        weights = TrustScoreWeights(
            identity_verification=0.50,
            vouch_count=0.10,
            bond_count=0.10,
            interaction_reputation=0.20,
            uptime_ratio=0.10,
        )
        score = compute_trust_score(True, 0, 0, 0.0, 0.0, weights)
        assert score == 0.5  # only identity verification contributes
