"""Tests for all ethics subsystem modules."""
import pytest
from ocp.ethics.risk_classification import RiskClassifier, RiskTier
from ocp.ethics.bias import BiasValidator, BiasDisclosure
from ocp.ethics.synthetic import SyntheticContentLabeler
from ocp.ethics.dual_use import DualUseClassifier, DualUseLevel
from ocp.ethics.consent import ConsentManager, ConsentToken
from ocp.ethics.transparency import TransparencyCard
from ocp.ethics.power_dynamics import PowerDynamicsMonitor
from ocp.ethics.cognitive import CognitiveDataProtector
from ocp.ethics.model_collapse import ModelCollapsePreventor
from ocp.ethics.sanctions import SanctionsScreener

@pytest.mark.asyncio
class TestRiskClassification:
    def test_healthcare_is_high(self):
        c = RiskClassifier()
        tier = c.classify(["healthcare.oncology"], ["cap:vision:imaging"])
        assert tier == RiskTier.HIGH

    def test_research_is_minimal(self):
        c = RiskClassifier()
        tier = c.classify(["research.literature_review"], ["cap:nlp:summarization"])
        assert tier == RiskTier.MINIMAL

    def test_lethal_force_is_unacceptable(self):
        c = RiskClassifier()
        tier = c.classify(["defense"], ["cap:custom:mil:lethal_force"])
        assert tier == RiskTier.UNACCEPTABLE

    def test_highest_tier_wins(self):
        c = RiskClassifier()
        tier = c.classify(["healthcare", "research"], ["cap:vision:imaging", "cap:nlp:summarization"])
        assert tier == RiskTier.HIGH

@pytest.mark.asyncio
class TestBiasValidator:
    def test_missing_disclosure_high_risk(self):
        v = BiasValidator()
        valid, warning = v.validate(None, risk_tier="high")
        assert not valid

    def test_complete_disclosure(self):
        v = BiasValidator()
        disc = {"known_biases": ["test"], "residual_risk": "low",
                "mitigation_applied": "resampling", "affected_subgroups": ["group_a"]}
        valid, warning = v.validate(disc, risk_tier="high")
        assert valid

@pytest.mark.asyncio
class TestSyntheticLabeler:
    def test_create_label(self):
        labeler = SyntheticContentLabeler()
        label = labeler.create_label("did:ocp:testnet:agent-001", "transformer_generation")
        assert label.is_synthetic
        assert label.generating_agent == "did:ocp:testnet:agent-001"

    def test_validate_complete(self):
        labeler = SyntheticContentLabeler()
        label_dict = {
            "is_synthetic": True, "generation_method": "gpt",
            "generating_agent": "did:ocp:testnet:agent-001",
            "generated_at": "2026-06-05T12:00:00Z"
        }
        valid, err = labeler.validate_label(label_dict)
        assert valid

    def test_validate_incomplete(self):
        labeler = SyntheticContentLabeler()
        valid, err = labeler.validate_label({"is_synthetic": True})
        assert not valid

    def test_append_transformation(self):
        labeler = SyntheticContentLabeler()
        label = {"is_synthetic": True, "generation_method": "gpt",
                 "generating_agent": "agent-a", "generated_at": "2026-01-01T00:00:00Z"}
        updated = labeler.append_transformation(label, "agent-b", "summarize")
        assert "agent-b:summarize" in updated["transformations"]

@pytest.mark.asyncio
class TestDualUse:
    def test_non_dual_use(self):
        c = DualUseClassifier()
        level = c.classify(["research.literature_review"])
        assert level == DualUseLevel.NO_CONCERN

    def test_dual_use_aware(self):
        c = DualUseClassifier()
        level = c.classify(["cybersecurity"])
        assert level == DualUseLevel.AWARE

    def test_dual_use_restricted(self):
        c = DualUseClassifier()
        level = c.classify(["virology"], {"methodology": "gain_of_function_analysis"})
        assert level == DualUseLevel.RESTRICTED

@pytest.mark.asyncio
class TestTransparencyCard:
    def test_valid_card(self):
        card = TransparencyCard(
            agent_id="did:ocp:testnet:agent-001",
            model_family="transformer",
            training_data_summary={"sources": ["pubmed"]},
            known_limitations=["English only"],
            intended_use_cases=["literature review"]
        )
        valid, issues = card.validate()
        assert valid

    def test_invalid_card(self):
        card = TransparencyCard()
        valid, issues = card.validate()
        assert not valid
        assert len(issues) > 0

@pytest.mark.asyncio
class TestPowerDynamics:
    def test_trust_asymmetry(self):
        m = PowerDynamicsMonitor()
        assert m.check_trust_asymmetry(4, 1) is True
        assert m.check_trust_asymmetry(2, 3) is False

    def test_dissolution_penalty_rejected(self):
        m = PowerDynamicsMonitor()
        bond = {"agents": ["a", "b"], "dissolution_penalty": 100}
        flags = m.check_bond_terms(bond)
        assert len(flags) == 1
        assert flags[0].flag_type == "exit_penalty"

@pytest.mark.asyncio
class TestCognitiveData:
    def test_detect_cognitive(self):
        p = CognitiveDataProtector()
        assert p.is_cognitive_data({"type": "eeg_signal"})
        assert not p.is_cognitive_data({"type": "text_summary"})

    def test_requires_consent(self):
        p = CognitiveDataProtector()
        valid, err = p.validate({"type": "neural_recording"}, {"consent_tokens": []})
        assert not valid

    def test_rejects_raw_neural(self):
        p = CognitiveDataProtector()
        valid, err = p.validate(
            {"type": "neural_data", "contains_raw_neural": True},
            {"consent_tokens": [{"basis": "explicit_cognitive_consent"}]}
        )
        assert not valid

@pytest.mark.asyncio
class TestModelCollapse:
    def test_high_generation_count(self):
        p = ModelCollapsePreventor()
        ok, msg = p.check_generation_count({"generation_count": 5})
        assert not ok

    def test_ok_generation_count(self):
        p = ModelCollapsePreventor()
        ok, msg = p.check_generation_count({"generation_count": 1})
        assert ok

    def test_excessive_ocp_ratio(self):
        p = ModelCollapsePreventor()
        ok, msg = p.check_ocp_source_ratio(0.8)
        assert not ok

    def test_ok_ocp_ratio(self):
        p = ModelCollapsePreventor()
        ok, msg = p.check_ocp_source_ratio(0.4)
        assert ok

    def test_increment_generation(self):
        p = ModelCollapsePreventor()
        prov = {"generation_count": 1, "source_agent": "test"}
        updated = p.increment_generation(prov)
        assert updated["generation_count"] == 2
        assert prov["generation_count"] == 1  # original unchanged

@pytest.mark.asyncio
class TestSanctions:
    @pytest.mark.asyncio
    async def test_clear_entity(self):
        s = SanctionsScreener()
        result = await s.screen("CleanCorp")
        assert result.cleared

    @pytest.mark.asyncio
    async def test_blocked_entity(self):
        s = SanctionsScreener()
        s.add_to_blocklist("SanctionedCorp")
        result = await s.screen("SanctionedCorp")
        assert not result.cleared
