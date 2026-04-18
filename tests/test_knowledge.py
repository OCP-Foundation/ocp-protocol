"""Tests for knowledge types — embeddings, insights, model deltas.

Compliance category: Knowledge Types (6 tests)
"""

import struct

import pytest

from ocp.knowledge import (
    EmbeddingPackage,
    EmbeddingVector,
    InsightFeature,
    InsightPackage,
    ModelDelta,
)


class TestEmbeddingPackage:
    """OCP-SPEC §4.3 — Type 1: Semantic embeddings."""

    def test_valid_embedding(self):
        vec = EmbeddingVector.from_floats("test", [0.1, 0.2, 0.3, 0.4], "research")
        pkg = EmbeddingPackage(dimensions=4, vectors=[vec])
        payload = pkg.to_payload()
        assert payload["knowledge_type"] == "embedding"
        assert payload["dimensions"] == 4
        assert payload["encoding"] == "float32"
        assert payload["normalization"] == "l2"
        assert len(payload["vectors"]) == 1
        assert payload["vectors"][0]["label"] == "test"

    def test_invalid_encoding_rejected(self):
        with pytest.raises(ValueError, match="encoding"):
            EmbeddingPackage(dimensions=4, vectors=[], encoding="int8")

    def test_invalid_normalization_rejected(self):
        with pytest.raises(ValueError, match="normalization"):
            EmbeddingPackage(dimensions=4, vectors=[], normalization="l1")

    def test_vector_dimensions_property(self):
        vec_bytes = struct.pack("8f", *range(8))
        vec = EmbeddingVector(label="test", vector=vec_bytes)
        assert vec.dimensions == 8


class TestInsightPackage:
    """OCP-SPEC §4.3 — Type 2: Insight packages."""

    def test_valid_insight(self, identity):
        pkg = InsightPackage(
            topic="fraud_detection",
            description="Velocity anomaly before large transfers",
            confidence=0.91,
            source_agent=identity.agent_id,
            derived_from="anonymized_logs",
            methodology="unsupervised_clustering",
            evidence_count=14203,
            features=[
                InsightFeature(name="tx_velocity", type="float", threshold=42.0, direction="above"),
            ],
            recommended_action="flag_for_review",
            false_positive_rate=0.03,
        )
        payload = pkg.to_payload()
        assert payload["knowledge_type"] == "insight"
        assert payload["anonymized"] is True  # hardcoded per spec
        assert payload["confidence"] == 0.91
        assert "provenance" in payload
        assert payload["provenance"]["source_agent"] == identity.agent_id
        assert payload["provenance"]["methodology"] == "unsupervised_clustering"
        assert "reproducibility_hash" in payload["provenance"]

    def test_confidence_too_high_rejected(self, identity):
        with pytest.raises(ValueError, match="Confidence"):
            InsightPackage(
                topic="t", description="d", confidence=1.5,
                source_agent=identity.agent_id, derived_from="x",
            )

    def test_confidence_negative_rejected(self, identity):
        with pytest.raises(ValueError, match="Confidence"):
            InsightPackage(
                topic="t", description="d", confidence=-0.1,
                source_agent=identity.agent_id, derived_from="x",
            )

    def test_empty_topic_rejected(self, identity):
        with pytest.raises(ValueError, match="Topic"):
            InsightPackage(
                topic="", description="d", confidence=0.5,
                source_agent=identity.agent_id, derived_from="x",
            )

    def test_anonymized_always_true(self, identity):
        pkg = InsightPackage(
            topic="t", description="d", confidence=0.5,
            source_agent=identity.agent_id, derived_from="x",
        )
        payload = pkg.to_payload()
        assert payload["anonymized"] is True


class TestModelDelta:
    """OCP-SPEC §4.3 — Type 3: Model deltas."""

    def test_valid_delta(self, identity):
        md = ModelDelta(
            architecture_family="transformer",
            parameter_count="7B",
            target_layers=["attn.q_proj", "attn.k_proj"],
            delta_payload=b"fake-delta-bytes",
            source_agent=identity.agent_id,
            training_samples=50000,
            epsilon=1.0,
            dp_delta=1e-5,
        )
        payload = md.to_payload()
        assert payload["knowledge_type"] == "model_delta"
        assert payload["differential_privacy"]["epsilon"] == 1.0
        assert payload["differential_privacy"]["mechanism"] == "gaussian"
        assert payload["provenance"]["training_samples"] == 50000

    def test_epsilon_above_max_rejected(self, identity):
        with pytest.raises(ValueError, match="Epsilon"):
            ModelDelta(
                architecture_family="t", parameter_count="1B",
                target_layers=["x"], delta_payload=b"x",
                source_agent=identity.agent_id, training_samples=1,
                epsilon=15.0, dp_delta=1e-5,
            )

    def test_epsilon_zero_rejected(self, identity):
        with pytest.raises(ValueError, match="Epsilon"):
            ModelDelta(
                architecture_family="t", parameter_count="1B",
                target_layers=["x"], delta_payload=b"x",
                source_agent=identity.agent_id, training_samples=1,
                epsilon=0, dp_delta=1e-5,
            )

    def test_invalid_format_rejected(self, identity):
        with pytest.raises(ValueError, match="format"):
            ModelDelta(
                architecture_family="t", parameter_count="1B",
                target_layers=["x"], delta_payload=b"x",
                source_agent=identity.agent_id, training_samples=1,
                epsilon=1.0, dp_delta=1e-5, format="invented",
            )

