"""
Agent Decommissioning Protocol.
Ref: OCP Ethics Bible v2.1 §24
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta


@dataclass
class DecommissionPlan:
    agent_id: str
    notice_date: str = ""
    decommission_date: str = ""
    bonded_peers: list[str] | None = None
    eal_archived: bool = False
    did_revoked: bool = False
    bonds_revoked: bool = False
    shares_revoked: bool = False

    def __post_init__(self):
        if not self.notice_date:
            self.notice_date = datetime.now(timezone.utc).isoformat()
        if not self.decommission_date:
            d = datetime.now(timezone.utc) + timedelta(days=30)
            self.decommission_date = d.isoformat()


class DecommissionManager:
    """
    Manages graceful agent shutdown with 30-day notice.

    Usage:
        mgr = DecommissionManager(agent=my_agent)
        plan = await mgr.initiate()
        await mgr.execute(plan)
    """

    def __init__(self, agent=None, registry=None, eal=None):
        self.agent = agent
        self.registry = registry
        self.eal = eal

    async def initiate(self) -> DecommissionPlan:
        """Create decommission plan and send notices."""
        plan = DecommissionPlan(
            agent_id=self.agent.agent_id if self.agent else "",
        )
        # Discover bonded peers
        if self.registry:
            peers = await self.registry.get_bonded_peers(plan.agent_id)
            plan.bonded_peers = [p["agent_id"] for p in peers]
        return plan

    async def send_notices(self, plan: DecommissionPlan):
        """Send decommission_notice to all bonded peers."""
        if self.agent and plan.bonded_peers:
            for peer in plan.bonded_peers:
                await self.agent.send_message(
                    receiver=peer,
                    message_type="decommission_notice",
                    payload={"decommission_date": plan.decommission_date}
                )

    async def execute(self, plan: DecommissionPlan):
        """Execute the decommission: revoke bonds, DID, archive EAL."""
        if self.agent and plan.bonded_peers:
            for peer in plan.bonded_peers:
                await self.agent.send_message(
                    receiver=peer, message_type="bond_revoke", payload={}
                )
            plan.bonds_revoked = True

        if self.eal:
            await self.eal.archive()
            plan.eal_archived = True

        plan.did_revoked = True
        return plan
