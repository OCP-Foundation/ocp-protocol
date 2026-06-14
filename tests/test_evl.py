"""Tests for Ethics Validation Layer (6-step pipeline)."""
import pytest
import asyncio
from ocp.ethics.evl import EVL, EVLResult
from ocp.ethics.eal import EAL
from ocp.ethics.pur import PUR
from ocp.ethics.consent import ConsentManager
from ocp.ethics.cascade import CascadeCircuitBreaker
from ocp.ethics.constants import EVLCode


@pytest.fixture
def pur():
    p = PUR()
    p.load_defaults()
    return p

@pytest.fixture
def eal():
    return EAL(node_id="did:ocp:testnet:node-test01")

@pytest.fixture
def consent_mgr():
    return ConsentManager()

@pytest.fixture
def cascade():
    return CascadeCircuitBreaker()

@pytest.fixture
def evl(pur, eal, consent_mgr, cascade):
    return EVL(pur=pur, eal=eal, consent_mgr=consent_mgr, cascade_breaker=cascade)


def make_message(msg_type="knowledge_share", tags=None, ethics=None, payload=None):
    return {
        "ocp_version": "1.0",
        "message_id": "msg-test-0001-0002-0003-0004",
        "timestamp": "2026-06-05T12:00:00Z",
        "sender": {"agent_id": "did:ocp:testnet:agent-sender01", "signature": "test"},
        "receiver": {"agent_id": "did:ocp:testnet:agent-recv01"},
        "message_type": msg_type,
        "payload": payload or {},
        "metadata": {"tags": tags or [], "ethics": ethics or {}},
    }

@pytest.mark.asyncio
class TestEVLPipeline:
    """Test the full 6-step EVL pipeline."""

    @pytest.mark.asyncio
    async def test_pass_clean_message(self, evl):
        msg = make_message(tags=["research"])
        result = await evl.validate(msg)
        assert result.status == "PASS"
        assert "prohibited_use_scan" in result.checks_performed

    @pytest.mark.asyncio
    async def test_reject_healthcare_no_consent(self, evl):
        msg = make_message(tags=["healthcare", "oncology"])
        result = await evl.validate(msg)
        assert result.status == "REJECT"
        assert result.code in (EVLCode.EVL_003, EVLCode.EVL_007)  # PUR or consent check

    @pytest.mark.asyncio
    async def test_pass_healthcare_with_consent(self, evl):
        ethics = {"consent_tokens": [{
            "token_id": "ct-test", "scope": "healthcare",
            "basis": "irb_approval", "reference": "IRB-TEST",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2027-01-01T00:00:00Z",
            "issuer": "did:ocp:testnet:agent-irb",
            "signature": "test"
        }]}
        msg = make_message(tags=["healthcare", "oncology"], ethics=ethics)
        result = await evl.validate(msg)
        assert result.status == "PASS"

    @pytest.mark.asyncio
    async def test_reject_autonomous_no_hitl(self, evl):
        payload = {
            "constraints": {
                "required_capabilities": ["cap:robotics:control"],
                "ethics": {"autonomous_execution": True}
            }
        }
        msg = make_message(msg_type="task_request", payload=payload)
        result = await evl.validate(msg)
        assert result.status == "REJECT"
        assert result.code == EVLCode.EVL_008

    @pytest.mark.asyncio
    async def test_pass_autonomous_with_approval(self, evl):
        ethics = {"human_approval": {
            "approver_id": "op-001", "approved_at": "2026-06-05T12:00:00Z",
            "method": "mfa_confirmed", "scope": "task-001", "signature": "test"
        }}
        payload = {
            "constraints": {
                "required_capabilities": ["cap:robotics:control"],
                "ethics": {"autonomous_execution": True}
            }
        }
        msg = make_message(msg_type="task_request", tags=[], ethics=ethics, payload=payload)
        result = await evl.validate(msg)
        assert result.status == "PASS"

    @pytest.mark.asyncio
    async def test_eal_logging(self, evl, eal):
        msg = make_message(tags=["research"])
        await evl.validate(msg)
        assert eal.length == 1
        assert eal.last_entry.evl_result == "PASS"

@pytest.mark.asyncio
class TestEAL:
    """Test Ethics Audit Log chain integrity."""

    @pytest.mark.asyncio
    async def test_chain_integrity(self, eal):
        from ocp.ethics.evl import EVLResult
        r = EVLResult(status="PASS", checks_performed=["test"])
        await eal.log("msg-1", "knowledge_share", "agent-a", "agent-b", r)
        await eal.log("msg-2", "task_request", "agent-a", "agent-c", r)
        assert await eal.verify_chain() is True

    @pytest.mark.asyncio
    async def test_chain_break_detection(self, eal):
        from ocp.ethics.evl import EVLResult
        r = EVLResult(status="PASS", checks_performed=["test"])
        await eal.log("msg-1", "test", "a", "b", r)
        # Tamper with the chain
        eal._chain[0].prev_hash = "tampered"
        with pytest.raises(Exception):
            await eal.verify_chain()

@pytest.mark.asyncio
class TestPUR:
    """Test Prohibited Use Registry pattern matching."""

    @pytest.mark.asyncio
    async def test_load_defaults(self, pur):
        assert pur.pattern_count == 10

    @pytest.mark.asyncio
    async def test_reject_version_downgrade(self, pur):
        from ocp.ethics.pur import ProhibitedUsePattern
        old = ProhibitedUsePattern(
            pur_id="pur-001", version=0, category="test",
            evl_code=EVLCode.EVL_001, description="old", pattern={}
        )
        assert pur.update(old) is False  # Reject downgrade

@pytest.mark.asyncio
class TestCascade:
    """Test cascade circuit breaker."""

    @pytest.mark.asyncio
    async def test_below_threshold(self, cascade):
        for i in range(10):
            cascade.record_propagation("msg-1", f"agent-{i}")
        assert await cascade.check("msg-1") is False

    @pytest.mark.asyncio
    async def test_above_threshold(self):
        breaker = CascadeCircuitBreaker(threshold_agents=5)
        for i in range(6):
            breaker.record_propagation("msg-1", f"agent-{i}")
        assert await breaker.check("msg-1") is True

    @pytest.mark.asyncio
    async def test_clear_pause(self):
        breaker = CascadeCircuitBreaker(threshold_agents=3)
        for i in range(4):
            breaker.record_propagation("msg-1", f"agent-{i}")
        assert await breaker.check("msg-1") is True
        breaker.clear_pause("msg-1", "agent-originator")
        assert await breaker.check("msg-1") is False
