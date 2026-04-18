"""Shared fixtures for the OCP compliance test suite.

All fixtures are session-scoped where possible to minimize key
generation overhead. Test-specific fixtures use function scope.
"""

from __future__ import annotations

import struct
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from ocp.crypto import SigningKeyPair, EncryptionKeyPair
from ocp.identity import AgentIdentity
from ocp.knowledge import (
    EmbeddingPackage,
    EmbeddingVector,
    InsightFeature,
    InsightPackage,
    ModelDelta,
)
from ocp.trust import Bond, BondPermissions, Vouch
from ocp.messages import MessageBuilder, MessageType


# ---- Identity fixtures ----

@pytest.fixture
def signing_keys() -> SigningKeyPair:
    return SigningKeyPair.generate()


@pytest.fixture
def encryption_keys() -> EncryptionKeyPair:
    return EncryptionKeyPair.generate()


@pytest.fixture
def identity() -> AgentIdentity:
    return AgentIdentity.generate(network="testnet")


@pytest.fixture
def peer_identity() -> AgentIdentity:
    return AgentIdentity.generate(network="testnet")


@pytest.fixture
def third_identity() -> AgentIdentity:
    return AgentIdentity.generate(network="testnet")


# ---- Message fixtures ----

@pytest.fixture
def sample_message(identity: AgentIdentity, peer_identity: AgentIdentity) -> dict[str, Any]:
    return (
        MessageBuilder(identity.agent_id, identity.signing_keys)
        .to(peer_identity.agent_id)
        .type(MessageType.DISCOVERY_PING)
        .payload({"capabilities": ["cap:nlp:classification"], "domains": ["research"]})
        .tag("research")
        .build()
    )


# ---- Knowledge fixtures ----

@pytest.fixture
def sample_insight_payload(identity: AgentIdentity) -> dict[str, Any]:
    return {
        "knowledge_type": "insight",
        "insight_id": "ins-test0001",
        "topic": "test_pattern_detection",
        "confidence": 0.85,
        "evidence_count": 100,
        "anonymized": True,
        "payload": {
            "pattern_id": "PAT-TEST0001",
            "description": "Test pattern for compliance suite validation",
            "features": [
                {"name": "feature_a", "type": "float", "threshold": 1.0, "direction": "above"}
            ],
            "recommended_action": "flag_for_review",
            "false_positive_rate": 0.05,
        },
        "provenance": {
            "source_agent": identity.agent_id,
            "derived_from": "synthetic_test_data",
            "methodology": "unit_test",
            "timestamp": "2026-04-03T12:00:00Z",
        },
    }


@pytest.fixture
def sample_model_delta_payload(identity: AgentIdentity) -> dict[str, Any]:
    return {
        "knowledge_type": "model_delta",
        "delta_id": "md-test0001",
        "format": "federated_avg",
        "compression": "gzip",
        "architecture": {
            "family": "transformer",
            "parameter_count": "7B",
            "target_layers": ["attention.q_proj"],
        },
        "differential_privacy": {
            "mechanism": "gaussian",
            "epsilon": 1.0,
            "delta": 1e-5,
            "noise_multiplier": 1.1,
        },
        "payload": "dGVzdC1kZWx0YQ",
        "provenance": {
            "source_agent": identity.agent_id,
            "training_samples": 1000,
            "timestamp": "2026-04-03T12:00:00Z",
        },
    }


@pytest.fixture
def sample_embedding_payload() -> dict[str, Any]:
    vec = struct.pack("4f", 0.1, 0.2, 0.3, 0.4)
    import base64
    return {
        "knowledge_type": "embedding",
        "encoding": "float32",
        "dimensions": 4,
        "model_family": "transformer",
        "normalization": "l2",
        "vectors": [
            {
                "id": "emb-test001",
                "label": "test_vector",
                "vector": base64.urlsafe_b64encode(vec).rstrip(b"=").decode(),
                "metadata": {"source_domain": "test", "created_at": "2026-04-03T12:00:00Z"},
            }
        ],
    }


# ---- Trust fixtures ----

@pytest.fixture
def sample_bond(identity: AgentIdentity, peer_identity: AgentIdentity) -> Bond:
    return Bond(
        agent_a=identity.agent_id,
        agent_b=peer_identity.agent_id,
        permissions=BondPermissions(
            knowledge_share=True,
            knowledge_allowed_types=["insight", "embedding"],
            task_delegate=True,
            model_delta_share=False,
        ),
    )


@pytest.fixture
def sample_vouch(identity: AgentIdentity, peer_identity: AgentIdentity) -> Vouch:
    return Vouch(
        attester_id=identity.agent_id,
        subject_id=peer_identity.agent_id,
        domains=["research", "nlp"],
        signing_keys=identity.signing_keys,
    )
