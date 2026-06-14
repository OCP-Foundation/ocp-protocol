"""
Transparency Card — agent self-disclosure document.
Ref: OCP Ethics Bible v2.1 §14 TR-002
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field


@dataclass
class TransparencyCard:
    """Agent transparency card published in DID Document."""
    agent_id: str = ""
    model_family: str = ""
    model_version: str = ""
    training_data_summary: dict = field(default_factory=dict)
    known_limitations: list[str] = field(default_factory=list)
    bias_test_results: dict = field(default_factory=dict)
    intended_use_cases: list[str] = field(default_factory=list)
    out_of_scope_uses: list[str] = field(default_factory=list)
    compute_footprint_estimate: dict = field(default_factory=dict)
    ocp_source_ratio: float = 0.0
    last_updated: str = ""

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, default=str)

    def validate(self) -> tuple[bool, list[str]]:
        """Check if card meets minimum requirements."""
        issues = []
        if not self.model_family:
            issues.append("model_family is required")
        if not self.training_data_summary:
            issues.append("training_data_summary is required")
        if not self.intended_use_cases:
            issues.append("intended_use_cases is required")
        if not self.known_limitations:
            issues.append("known_limitations is required")
        return len(issues) == 0, issues
