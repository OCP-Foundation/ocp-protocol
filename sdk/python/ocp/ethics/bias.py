"""
Bias Disclosure validation subsystem.
Ref: OCP Ethics Bible v2.1 §12
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class BiasDisclosure:
    """Structured bias disclosure for knowledge payloads."""
    known_biases: list[str] = field(default_factory=list)
    mitigation_applied: str = ""
    residual_risk: str = ""  # "low", "medium", "high"
    affected_subgroups: list[str] = field(default_factory=list)
    recommendation: str = ""

    def is_complete(self) -> bool:
        return bool(self.known_biases and self.residual_risk)

    def to_dict(self) -> dict:
        return {
            "known_biases": self.known_biases,
            "mitigation_applied": self.mitigation_applied,
            "residual_risk": self.residual_risk,
            "affected_subgroups": self.affected_subgroups,
            "recommendation": self.recommendation,
        }


class BiasValidator:
    """Validates bias disclosures and checks for completeness."""

    PROTECTED_CHARACTERISTICS = frozenset([
        "race", "ethnicity", "color", "sex", "gender_identity",
        "sexual_orientation", "age", "disability", "religion",
        "national_origin", "language", "socioeconomic_status",
        "political_opinion",
    ])

    def validate(self, disclosure: dict | None, risk_tier: str = "limited") -> tuple[bool, str | None]:
        """Returns (is_valid, warning_message)."""
        if not disclosure:
            if risk_tier in ("high",):
                return False, "Missing bias_disclosure on high-risk payload"
            return True, None

        bd = BiasDisclosure(**{k: v for k, v in disclosure.items()
                               if k in BiasDisclosure.__dataclass_fields__})
        if not bd.is_complete():
            return False, "Incomplete bias_disclosure: needs known_biases and residual_risk"

        return True, None

    def check_intersectional(self, disclosure: dict) -> list[str]:
        """Flag missing intersectional analysis for high-risk domains."""
        warnings = []
        subgroups = disclosure.get("affected_subgroups", [])
        if len(subgroups) < 2:
            warnings.append("Consider intersectional bias analysis across multiple subgroups")
        return warnings
