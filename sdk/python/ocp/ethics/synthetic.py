"""
Synthetic Content Labeling Engine.
Ref: OCP Ethics Bible v2.1 §26
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class SyntheticLabel:
    """Label for AI-generated or substantially modified content."""
    is_synthetic: bool = True
    generation_method: str = ""
    generating_agent: str = ""
    generated_at: str = ""
    watermark_id: str | None = None
    transformations: list[str] | None = None

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        d = {
            "is_synthetic": self.is_synthetic,
            "generation_method": self.generation_method,
            "generating_agent": self.generating_agent,
            "generated_at": self.generated_at,
        }
        if self.watermark_id:
            d["watermark_id"] = self.watermark_id
        if self.transformations:
            d["transformations"] = self.transformations
        return d


class SyntheticContentLabeler:
    """Creates and validates synthetic content labels."""

    def create_label(self, agent_id: str, method: str,
                     watermark: bool = False) -> SyntheticLabel:
        label = SyntheticLabel(
            generation_method=method,
            generating_agent=agent_id,
        )
        if watermark:
            label.watermark_id = f"wm-{uuid.uuid4()}"
        return label

    def validate_label(self, label_dict: dict | None) -> tuple[bool, str | None]:
        """Validate a synthetic content label has all required fields."""
        if not label_dict:
            return False, "Missing synthetic_content label"
        required = {"is_synthetic", "generation_method", "generating_agent", "generated_at"}
        missing = required - label_dict.keys()
        if missing:
            return False, f"Incomplete label, missing: {missing}"
        return True, None

    def append_transformation(self, label_dict: dict, agent_id: str,
                               transformation: str) -> dict:
        """Append a transformation to an existing label (for re-sharing chains)."""
        label_dict = dict(label_dict)
        transforms = label_dict.get("transformations", []) or []
        transforms.append(f"{agent_id}:{transformation}")
        label_dict["transformations"] = transforms
        return label_dict
