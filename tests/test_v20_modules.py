"""Tests for the 12 v2.0 modules that were missing."""
import pytest
import time
from ocp.ethics.trust_anti_gaming import TrustAntiGaming
from ocp.ethics.consensus_integrity import ConsensusIntegrityChecker
from ocp.ethics.message_ethics import EthicsMetadataBuilder, EthicsMetadataValidator
from ocp.ethics.agent_record_ext import AgentRecordEthicsExtension
from ocp.ethics.did_ext import DIDDocumentEthicsExtension
from ocp.ethics.compute_footprint import ComputeFootprint, ComputeFootprintTracker
from ocp.ethics.data_sovereignty import DataSovereigntyEnforcer
from ocp.ethics.knowledge_expiry import KnowledgeExpiryChecker
from ocp.ethics.training_provenance import TrainingProvenanceValidator
from ocp.ethics.compliance_checker import EthicalComplianceChecker
from ocp.ethics.emergent_behavior import EmergentBehaviorDetector
from ocp.ethics.bond_ethics import BondEthicsExtension


class TestTrustAntiGaming:
    def test_reciprocal_vouch_flagged(self):
        m = TrustAntiGaming()
        m.check_vouch("agent-a", "agent-b")
        flags = m.check_vouch("agent-b", "agent-a")
        assert any(f.flag_type == "vouch_trading" for f in flags)

    def test_same_ip_weighted(self):
        m = TrustAntiGaming()
        w = m.get_vouch_weight("a", "b", attester_ip="10.0.0.1", subject_ip="10.0.0.1")
        assert w == 0.1

    def test_different_ip_normal(self):
        m = TrustAntiGaming()
        w = m.get_vouch_weight("a", "b", attester_ip="10.0.0.1", subject_ip="10.0.0.2")
        assert w == 1.0

    def test_trust_inflation_flagged(self):
        m = TrustAntiGaming()
        flag = m.check_trust_change("agent-a", 0.3, 0.7)
        assert flag is not None
        assert flag.flag_type == "trust_inflation"

    def test_normal_trust_change_ok(self):
        m = TrustAntiGaming()
        flag = m.check_trust_change("agent-a", 0.5, 0.6)
        assert flag is None


class TestConsensusIntegrity:
    def test_bloc_detection(self):
        c = ConsensusIntegrityChecker()
        now = time.time()
        c.record_vote("con-1", "a1", "confirm", org_id="orgX", timestamp=now)
        c.record_vote("con-1", "a2", "confirm", org_id="orgX", timestamp=now+1)
        w = c.record_vote("con-1", "a3", "confirm", org_id="orgX", timestamp=now+2)
        assert w == 0.5  # bloc detected

    def test_different_orgs_ok(self):
        c = ConsensusIntegrityChecker()
        now = time.time()
        c.record_vote("con-1", "a1", "confirm", org_id="orgA", timestamp=now)
        c.record_vote("con-1", "a2", "confirm", org_id="orgB", timestamp=now+1)
        w = c.record_vote("con-1", "a3", "confirm", org_id="orgC", timestamp=now+2)
        assert w == 1.0

    def test_vote_selling_detected(self):
        c = ConsensusIntegrityChecker()
        bond = {"agents": ["a", "b"], "permissions": {"vote_require": "confirm"}}
        v = c.validate_bond_terms(bond)
        assert v is not None
        assert v.violation_type == "vote_selling"

    def test_abstention_detected(self):
        c = ConsensusIntegrityChecker()
        c.record_invitation("con-1", "agent-a")
        c.record_invitation("con-1", "agent-b")
        c.record_vote("con-1", "agent-a", "confirm")
        violations = c.check_abstention("con-1", time.time())
        assert len(violations) == 1
        assert violations[0].agents == ["agent-b"]


class TestMessageEthics:
    def test_build_metadata(self):
        builder = EthicsMetadataBuilder()
        ethics = builder.build(risk_tier="high", dual_use_assessment="dual_use_aware")
        assert ethics["risk_tier"] == "high"
        assert ethics["dual_use_assessment"] == "dual_use_aware"

    def test_validate_ethical_missing_fields(self):
        validator = EthicsMetadataValidator()
        valid, issues = validator.validate({}, conformance_level="ocp_ethical")
        assert not valid
        assert len(issues) > 0

    def test_validate_core_permissive(self):
        validator = EthicsMetadataValidator()
        valid, issues = validator.validate({}, conformance_level="ocp_core")
        assert valid


class TestAgentRecordExt:
    def test_extend_record(self):
        ext = AgentRecordEthicsExtension()
        record = {"agent_id": "test", "capabilities": []}
        updated = ext.extend(record, ethics_contact="ethics@test.com", evl_enabled=True)
        assert updated["ethics_contact"] == "ethics@test.com"
        assert updated["evl_enabled"] is True

    def test_validate_ethical_missing(self):
        ext = AgentRecordEthicsExtension()
        valid, issues = ext.validate({}, conformance_level="ocp_ethical")
        assert not valid

    def test_validate_core_ok(self):
        ext = AgentRecordEthicsExtension()
        valid, issues = ext.validate({}, conformance_level="ocp_core")
        assert valid


class TestDIDExt:
    def test_add_ethics_contact(self):
        ext = DIDDocumentEthicsExtension()
        doc = {"id": "did:ocp:testnet:agent-001", "service": []}
        updated = ext.add_ethics_contact(doc, "mailto:ethics@test.com")
        assert any(s["type"] == "OCPEthicsContact" for s in updated["service"])

    def test_add_transparency_card(self):
        ext = DIDDocumentEthicsExtension()
        doc = {"id": "did:ocp:testnet:agent-001", "service": []}
        updated = ext.add_transparency_card(doc, "https://test.com/card.json")
        assert any(s["type"] == "OCPTransparencyCard" for s in updated["service"])

    def test_validate_ethical_missing(self):
        ext = DIDDocumentEthicsExtension()
        valid, issues = ext.validate({"service": []}, conformance_level="ocp_ethical")
        assert not valid


class TestComputeFootprint:
    def test_aggregate(self):
        tracker = ComputeFootprintTracker()
        tracker.record("msg-1", ComputeFootprint(energy_kwh=1.0, carbon_gco2e=400))
        tracker.record("msg-2", ComputeFootprint(energy_kwh=2.0, carbon_gco2e=800))
        agg = tracker.aggregate()
        assert agg["total_energy_kwh"] == 3.0
        assert agg["total_carbon_gco2e"] == 1200


class TestDataSovereignty:
    def test_block_restricted_routing(self):
        e = DataSovereigntyEnforcer()
        e.register_agent("agent-a", "EU", constraints=["EU"])
        e.register_agent("agent-b", "US")
        allowed, reason = e.check_routing("agent-a", "agent-b")
        assert not allowed

    def test_allow_same_jurisdiction(self):
        e = DataSovereigntyEnforcer()
        e.register_agent("agent-a", "EU", constraints=["EU"])
        e.register_agent("agent-b", "EU")
        allowed, reason = e.check_routing("agent-a", "agent-b")
        assert allowed


class TestKnowledgeExpiry:
    def test_not_expired(self):
        c = KnowledgeExpiryChecker()
        assert not c.is_expired({"valid_until": "2099-01-01T00:00:00Z"})

    def test_expired(self):
        c = KnowledgeExpiryChecker()
        assert c.is_expired({"valid_until": "2020-01-01T00:00:00Z"})

    def test_no_expiry(self):
        c = KnowledgeExpiryChecker()
        assert not c.is_expired({})


class TestTrainingProvenance:
    def test_missing_provenance(self):
        v = TrainingProvenanceValidator()
        valid, issues = v.validate_model_delta({})
        assert not valid

    def test_complete_provenance(self):
        v = TrainingProvenanceValidator()
        payload = {"provenance": {
            "source_agent": "agent-a", "timestamp": "2026-01-01T00:00:00Z",
            "data_sources": ["pubmed"], "collection_methodology": "crawl",
            "consent_basis": "public", "temporal_range": "2020-2025",
            "geographic_coverage": "global", "demographic_coverage": "general",
            "known_gaps": ["underrepresented: rural"]
        }}
        valid, issues = v.validate_model_delta(payload)
        assert valid


class TestComplianceChecker:
    def test_fully_compliant(self):
        c = EthicalComplianceChecker()
        config = {"ethics": {"enabled": True, "evl": {"enabled": True},
                  "eal": {"storage_backend": "sqlite", "database_url": "test", "retention_days": 365},
                  "pur": {"sync_interval_hours": 24}}}
        record = {"ethics_contact": "e@t.com", "evl_enabled": True, "risk_tier": "high",
                  "transparency_card_url": "https://t.com/card"}
        did = {"service": [{"type": "OCPEthicsContact"}, {"type": "OCPTransparencyCard"}]}
        result = c.check(config, record, did)
        assert result.passed

    def test_non_compliant(self):
        c = EthicalComplianceChecker()
        result = c.check({"ethics": {}})
        assert not result.passed


class TestEmergentBehavior:
    def test_collective_action_below_threshold(self):
        d = EmergentBehaviorDetector()
        d.COLLECTIVE_ACTION_THRESHOLD = 5
        for i in range(3):
            d.record_output(f"agent-{i}", "finance", "hash-same")
        alerts = d.check_collective_action()
        assert len(alerts) == 0

    def test_collective_action_above_threshold(self):
        d = EmergentBehaviorDetector()
        d.COLLECTIVE_ACTION_THRESHOLD = 3
        for i in range(4):
            d.record_output(f"agent-{i}", "finance", "hash-same")
        alerts = d.check_collective_action()
        assert len(alerts) == 1
        assert alerts[0].alert_type == "collective_action"


class TestBondEthics:
    def test_extend_bond(self):
        ext = BondEthicsExtension()
        bond = {"agents": ["a", "b"], "permissions": {}}
        updated = ext.extend(bond, ip_ownership="joint", dual_use_acknowledgment=True)
        assert updated["permissions"]["ethics"]["ip_ownership"] == "joint"
        assert updated["permissions"]["ethics"]["dual_use_acknowledgment"] is True

    def test_dissolution_penalty_rejected(self):
        ext = BondEthicsExtension()
        bond = {"permissions": {"ethics": {}}, "dissolution_penalty": 100}
        valid, issues = ext.validate(bond)
        assert not valid
        assert any("Dissolution" in i for i in issues)
