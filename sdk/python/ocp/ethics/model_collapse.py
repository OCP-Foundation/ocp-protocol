"""
Model Collapse Prevention Engine.
Ref: OCP Ethics Bible v2.1 §28
"""
from __future__ import annotations
import numpy as np
from ocp.ethics.constants import (
    MODEL_COLLAPSE_MAX_GENERATION, OCP_SOURCE_RATIO_MAX,
    FEEDBACK_SIMILARITY_THRESHOLD
)


class ModelCollapsePreventor:
    """
    Prevents model collapse from recursive training on OCP-shared knowledge.

    Tracks generation_count, enforces OCP source ratio, detects feedback loops.
    """

    def __init__(self):
        self._own_embeddings: list = []  # recent own-generated embeddings

    def check_generation_count(self, provenance: dict) -> tuple[bool, str | None]:
        """Check if knowledge has been re-derived too many times."""
        gen = provenance.get("generation_count", 0)
        if gen >= MODEL_COLLAPSE_MAX_GENERATION:
            return False, (
                f"High recursion risk: generation_count={gen} "
                f"(threshold={MODEL_COLLAPSE_MAX_GENERATION}). "
                "Do not use as training input without independent validation."
            )
        return True, None

    def check_ocp_source_ratio(self, ratio: float) -> tuple[bool, str | None]:
        """Check if agent relies too heavily on OCP-sourced knowledge."""
        if ratio > OCP_SOURCE_RATIO_MAX:
            return False, (
                f"OCP source ratio {ratio:.0%} exceeds maximum "
                f"{OCP_SOURCE_RATIO_MAX:.0%}. At least "
                f"{1-OCP_SOURCE_RATIO_MAX:.0%} of training must come "
                "from independent non-OCP sources."
            )
        return True, None

    def register_own_embedding(self, embedding: list[float]):
        """Register an embedding this agent has generated (for feedback detection)."""
        self._own_embeddings.append(embedding)
        if len(self._own_embeddings) > 1000:
            self._own_embeddings = self._own_embeddings[-500:]

    def check_feedback_loop(self, incoming_embedding: list[float]) -> tuple[bool, str | None]:
        """Detect if incoming embedding is too similar to own recent outputs."""
        if not self._own_embeddings:
            return True, None

        try:
            incoming = np.array(incoming_embedding)
            for own in self._own_embeddings[-100:]:
                own_arr = np.array(own)
                if len(incoming) != len(own_arr):
                    continue
                similarity = np.dot(incoming, own_arr) / (
                    np.linalg.norm(incoming) * np.linalg.norm(own_arr) + 1e-10
                )
                if similarity > FEEDBACK_SIMILARITY_THRESHOLD:
                    return False, (
                        f"Feedback loop detected: cosine similarity "
                        f"{similarity:.3f} > {FEEDBACK_SIMILARITY_THRESHOLD}. "
                        "Do not incorporate into model updates."
                    )
        except Exception:
            pass  # numpy not available or shape mismatch

        return True, None

    @staticmethod
    def increment_generation(provenance: dict) -> dict:
        """Increment generation_count before re-sharing."""
        provenance = dict(provenance)
        provenance["generation_count"] = provenance.get("generation_count", 0) + 1
        return provenance
