"""
Training Data Provenance Validation.
Ref: Integration Spec INT-015, Ethics Bible §23

Validates training data documentation for model deltas.
"""
from __future__ import annotations


class TrainingProvenanceValidator:
    """
    Validates training data provenance in model deltas and transparency cards.

    Usage:
        validator = TrainingProvenanceValidator()
        valid, issues = validator.validate_model_delta(delta_payload)
    """

    REQUIRED_PROVENANCE_FIELDS = {"source_agent", "timestamp"}
    RECOMMENDED_TRAINING_FIELDS = {
        "data_sources", "collection_methodology", "consent_basis",
        "temporal_range", "geographic_coverage", "demographic_coverage",
        "known_gaps"
    }

    def validate_model_delta(self, payload: dict) -> tuple[bool, list[str]]:
        """Validate provenance in a model delta payload."""
        issues = []
        provenance = payload.get("provenance", {})

        if not provenance:
            issues.append("Model delta missing provenance field entirely")
            return False, issues

        for field in self.REQUIRED_PROVENANCE_FIELDS:
            if field not in provenance:
                issues.append(f"Provenance missing required field: {field}")

        # Check training-specific fields
        for field in self.RECOMMENDED_TRAINING_FIELDS:
            if field not in provenance:
                issues.append(f"Provenance missing recommended field: {field}")

        # Check for synthetic data disclosure
        if provenance.get("includes_synthetic_data") and not provenance.get("synthetic_methodology"):
            issues.append("Synthetic training data must disclose generation methodology")

        return len(issues) == 0, issues

    def validate_transparency_card_training(self, card: dict) -> tuple[bool, list[str]]:
        """Validate training data section of a transparency card."""
        issues = []
        training = card.get("training_data_summary", {})

        if not training:
            issues.append("Transparency card missing training_data_summary")
            return False, issues

        if not training.get("sources"):
            issues.append("training_data_summary missing sources")
        if not training.get("consent_basis"):
            issues.append("training_data_summary missing consent_basis")

        return len(issues) == 0, issues
