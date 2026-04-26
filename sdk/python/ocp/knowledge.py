"""Knowledge types: embeddings, insights, and model deltas.

OCP defines three types of shareable knowledge. This module provides
dataclass-based builders for each type, with validation and serialization
to OCP-compliant payload dicts.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ocp.constants import MAX_EPSILON
from ocp.crypto import b64url_encode, generate_uuid_short, sha3_256_hex


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ==========================================================================
# Type 1: Semantic Embeddings
# ==========================================================================

@dataclass
class EmbeddingVector:
    """A single labeled embedding vector.

    Attributes:
        label: Human-readable label for this vector.
        vector: Raw bytes of the float array.
        source_domain: Domain this embedding relates to.
        id: Unique vector identifier (auto-generated if not provided).
        created_at: Creation timestamp.
    """

    label: str
    vector: bytes
    source_domain: str = ""
    id: str = field(default_factory=lambda: f"emb-{uuid.uuid4().hex[:8]}")
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to OCP embedding vector dict."""
        return {
            "id": self.id,
            "label": self.label,
            "vector": b64url_encode(self.vector),
            "metadata": {
                "source_domain": self.source_domain,
                "created_at": self.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        }

    @property
    def dimensions(self) -> int:
        """Infer dimensionality assuming float32 encoding."""
        return len(self.vector) // 4

    @staticmethod
    def from_floats(label: str, values: list[float], source_domain: str = "") -> EmbeddingVector:
        """Create a vector from a list of Python floats.

        Args:
            label: Human-readable label.
            values: List of float values.
            source_domain: Domain tag.

        Returns:
            An :class:`EmbeddingVector` with float32-packed bytes.
        """
        raw = struct.pack(f"{len(values)}f", *values)
        return EmbeddingVector(label=label, vector=raw, source_domain=source_domain)


@dataclass
class EmbeddingPackage:
    """Type 1 knowledge: a package of semantic embeddings.

    Attributes:
        dimensions: Number of dimensions per vector.
        vectors: List of :class:`EmbeddingVector` entries.
        encoding: Float encoding format (``"float32"``, ``"float16"``, ``"bfloat16"``).
        model_family: Architecture family that generated the embeddings.
        normalization: Normalization scheme (``"l2"`` or ``"none"``).
    """

    dimensions: int
    vectors: list[EmbeddingVector]
    encoding: str = "float32"
    model_family: str = "transformer"
    normalization: str = "l2"

    def __post_init__(self) -> None:
        if self.encoding not in ("float32", "float16", "bfloat16"):
            raise ValueError(f"Unsupported encoding: {self.encoding}")
        if self.normalization not in ("l2", "none"):
            raise ValueError(f"Unsupported normalization: {self.normalization}")
        if self.dimensions < 1:
            raise ValueError("Dimensions must be >= 1")

    def to_payload(self) -> dict[str, Any]:
        """Serialize to an OCP knowledge payload dict.

        Returns:
            Dict ready to be used as a ``knowledge_share`` message payload.
        """
        return {
            "knowledge_type": "embedding",
            "encoding": self.encoding,
            "dimensions": self.dimensions,
            "model_family": self.model_family,
            "normalization": self.normalization,
            "vectors": [v.to_dict() for v in self.vectors],
        }


# ==========================================================================
# Type 2: Insight Packages
# ==========================================================================

@dataclass
class InsightFeature:
    """A single feature within an insight pattern.

    Attributes:
        name: Feature identifier (e.g., ``"tx_velocity_5min"``).
        type: Data type (e.g., ``"float"``, ``"int"``, ``"bool"``).
        threshold: Threshold value for triggering.
        direction: Direction relative to threshold (``"above"``, ``"below"``, ``"equal"``).
    """

    name: str
    type: str
    threshold: float | None = None
    direction: str | None = None

    def __post_init__(self) -> None:
        if self.direction is not None and self.direction not in ("above", "below", "equal"):
            raise ValueError(f"Invalid direction: {self.direction}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        d: dict[str, Any] = {"name": self.name, "type": self.type}
        if self.threshold is not None:
            d["threshold"] = self.threshold
        if self.direction is not None:
            d["direction"] = self.direction
        return d


@dataclass
class InsightPackage:
    """Type 2 knowledge: a structured insight package.

    Attributes:
        topic: Subject of the insight.
        description: Human-readable description of the finding.
        confidence: Confidence score in [0.0, 1.0].
        source_agent: DID of the agent that produced this insight.
        derived_from: Description of the source data (must be anonymized).
        features: List of :class:`InsightFeature` entries.
        category: Classification category.
        evidence_count: Number of evidence samples.
        recommended_action: Suggested action for recipients.
        false_positive_rate: Estimated FPR if applicable.
        methodology: Method used to derive the insight.
    """

    topic: str
    description: str
    confidence: float
    source_agent: str
    derived_from: str
    features: list[InsightFeature] = field(default_factory=list)
    category: str = ""
    evidence_count: int = 0
    recommended_action: str = ""
    false_positive_rate: float | None = None
    methodology: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if self.false_positive_rate is not None and not 0.0 <= self.false_positive_rate <= 1.0:
            raise ValueError(f"False positive rate must be between 0.0 and 1.0")
        if not self.topic:
            raise ValueError("Topic is required")
        if not self.source_agent:
            raise ValueError("Source agent DID is required")

    def to_payload(self) -> dict[str, Any]:
        """Serialize to an OCP knowledge payload dict.

        The ``anonymized`` field is always set to ``True`` per the OCP spec.

        Returns:
            Dict ready for use as a ``knowledge_share`` message payload.
        """
        insight_id = generate_uuid_short("ins-")
        pattern_id = f"PAT-{uuid.uuid4().hex[:8].upper()}"

        inner_payload: dict[str, Any] = {
            "pattern_id": pattern_id,
            "description": self.description,
            "features": [f.to_dict() for f in self.features],
            "recommended_action": self.recommended_action,
        }
        if self.false_positive_rate is not None:
            inner_payload["false_positive_rate"] = self.false_positive_rate

        provenance: dict[str, Any] = {
            "source_agent": self.source_agent,
            "derived_from": self.derived_from,
            "timestamp": _utcnow_iso(),
        }
        if self.methodology:
            provenance["methodology"] = self.methodology
            provenance["reproducibility_hash"] = sha3_256_hex(
                f"{self.methodology}:{self.topic}".encode()
            )[:32]

        result: dict[str, Any] = {
            "knowledge_type": "insight",
            "insight_id": insight_id,
            "topic": self.topic,
            "confidence": self.confidence,
            "evidence_count": self.evidence_count,
            "anonymized": True,
            "payload": inner_payload,
            "provenance": provenance,
        }
        if self.category:
            result["category"] = self.category

        return result


# ==========================================================================
# Type 3: Model Deltas
# ==========================================================================

@dataclass
class ModelDelta:
    """Type 3 knowledge: privacy-safe model deltas.

    All model deltas **must** include differential privacy parameters.
    The OCP spec enforces a maximum epsilon of 10.0.

    Attributes:
        architecture_family: Model architecture (e.g., ``"transformer"``).
        parameter_count: Human-readable parameter count (e.g., ``"7B"``).
        target_layers: List of layer identifiers the delta applies to.
        delta_payload: Raw delta bytes (compressed).
        source_agent: DID of the producing agent.
        training_samples: Number of training samples used.
        epsilon: Differential privacy epsilon.
        dp_delta: Differential privacy delta.
        format: Delta format (``"federated_avg"``, ``"federated_sgd"``, ``"lora_delta"``, ``"adapter"``).
        compression: Compression algorithm (``"none"``, ``"gzip"``, ``"zstd"``).
        noise_multiplier: DP noise multiplier.
        dp_mechanism: DP mechanism (``"gaussian"`` or ``"laplace"``).
    """

    architecture_family: str
    parameter_count: str
    target_layers: list[str]
    delta_payload: bytes
    source_agent: str
    training_samples: int
    epsilon: float
    dp_delta: float
    format: str = "federated_avg"
    compression: str = "gzip"
    noise_multiplier: float = 1.1
    dp_mechanism: str = "gaussian"

    def __post_init__(self) -> None:
        if self.epsilon > MAX_EPSILON:
            raise ValueError(f"Epsilon must be <= {MAX_EPSILON}, got {self.epsilon}")
        if self.epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if self.dp_delta <= 0 or self.dp_delta >= 1:
            raise ValueError("DP delta must be in (0, 1)")
        if self.format not in ("federated_avg", "federated_sgd", "lora_delta", "adapter"):
            raise ValueError(f"Unsupported format: {self.format}")
        if self.compression not in ("none", "gzip", "zstd"):
            raise ValueError(f"Unsupported compression: {self.compression}")
        if self.dp_mechanism not in ("gaussian", "laplace"):
            raise ValueError(f"Unsupported DP mechanism: {self.dp_mechanism}")
        if self.training_samples < 1:
            raise ValueError("Training samples must be >= 1")

    def to_payload(self) -> dict[str, Any]:
        """Serialize to an OCP knowledge payload dict.

        Returns:
            Dict ready for use as a ``knowledge_share`` message payload.
        """
        return {
            "knowledge_type": "model_delta",
            "delta_id": generate_uuid_short("md-"),
            "format": self.format,
            "compression": self.compression,
            "architecture": {
                "family": self.architecture_family,
                "parameter_count": self.parameter_count,
                "target_layers": self.target_layers,
            },
            "differential_privacy": {
                "mechanism": self.dp_mechanism,
                "epsilon": self.epsilon,
                "delta": self.dp_delta,
                "noise_multiplier": self.noise_multiplier,
            },
            "payload": b64url_encode(self.delta_payload),
            "provenance": {
                "source_agent": self.source_agent,
                "training_samples": self.training_samples,
                "timestamp": _utcnow_iso(),
            },
        }
