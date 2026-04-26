"""High-level Agent class — the main entry point for the OCP SDK.

The :class:`Agent` class is the primary interface for building OCP-enabled
AI systems. It wraps identity management, transport, registry, trust,
knowledge sharing, task delegation, and consensus into a single coherent API.

Usage::

    agent = Agent(
        name="MyFinanceAI",
        capabilities=["nlp:classification", "finance:risk_analysis"],
        domains=["finance"],
        service_endpoint="wss://my-ai.example.com/ocp/v1/ws",
    )

    await agent.register()
    peers = await agent.discover(domain="finance")
    await agent.share(insight, to=peers[0]["agent_id"])
    await agent.close()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ocp.consensus import ConsensusConfig, ConsensusRound
from ocp.crypto import b64url_encode, generate_uuid_short
from ocp.exceptions import OCPTrustError, OCPValidationError
from ocp.identity import AgentIdentity
from ocp.knowledge import EmbeddingPackage, InsightPackage, ModelDelta
from ocp.messages import MessageBuilder, MessageType, Priority
from ocp.pvl import enforce_pvl
from ocp.recovery import RecoveryManager
from ocp.registry import AgentRecord, RegistryClient, RegistryConfig
from ocp.transport import HTTPTransport, TransportConfig, WebSocketTransport
from ocp.trust import Bond, BondPermissions, TrustLevel, Vouch

logger = logging.getLogger("ocp.agent")


@dataclass
class Agent:
    """An OCP agent — the primary interface for protocol participation.

    Attributes:
        name: Human-readable agent name.
        capabilities: List of capability identifiers (e.g., ``"nlp:classification"``).
        domains: List of domain identifiers (e.g., ``"finance"``).
        network: Network identifier.
        service_endpoint: This agent's OCP messaging endpoint URL.
        registry_url: URL of the Agent Registry.
    """

    name: str
    capabilities: list[str]
    domains: list[str]
    network: str = "mainnet"
    service_endpoint: str = ""
    registry_url: str = "https://registry.opencognitionprotocol.org/ocp/v1"

    # Private state (initialized in __post_init__)
    _identity: AgentIdentity | None = field(default=None, repr=False, init=False)
    _registry: RegistryClient | None = field(default=None, repr=False, init=False)
    _ws_transport: WebSocketTransport | None = field(default=None, repr=False, init=False)
    _http_transport: HTTPTransport | None = field(default=None, repr=False, init=False)
    _bonds: dict[str, Bond] = field(default_factory=dict, repr=False, init=False)
    _vouches_received: list[Vouch] = field(default_factory=list, repr=False, init=False)
    _vouches_given: list[Vouch] = field(default_factory=list, repr=False, init=False)
    _active_consensus: dict[str, ConsensusRound] = field(default_factory=dict, repr=False, init=False)
    _recovery_manager: RecoveryManager | None = field(default=None, repr=False, init=False)

    def __post_init__(self) -> None:
        self._identity = AgentIdentity.generate(network=self.network)
        self._registry = RegistryClient(RegistryConfig(base_url=self.registry_url))
        self._recovery_manager = RecoveryManager(self.agent_id, self._identity.signing_keys)
        logger.info("Agent created: %s (%s)", self.name, self.agent_id)

    # ---- Properties ----

    @property
    def agent_id(self) -> str:
        """The agent's DID."""
        assert self._identity is not None
        return self._identity.agent_id

    @property
    def identity(self) -> AgentIdentity:
        """The agent's full cryptographic identity."""
        assert self._identity is not None
        return self._identity

    @property
    def trust_level(self) -> TrustLevel:
        """The agent's current trust level based on local state."""
        from ocp.trust import determine_trust_level
        return determine_trust_level(
            is_verified=True,
            vouch_count=len([v for v in self._vouches_received if v.is_valid]),
            bond_count=len([b for b in self._bonds.values() if b.is_active]),
        )

    @property
    def bonds(self) -> dict[str, Bond]:
        """Active bonds keyed by peer agent ID."""
        return {k: v for k, v in self._bonds.items() if v.is_active}

    @property
    def recovery_manager(self) -> RecoveryManager:
        """Access the key recovery manager."""
        assert self._recovery_manager is not None
        return self._recovery_manager

    # ---- Registration ----

    async def register(self) -> dict[str, Any]:
        """Register this agent on the OCP network.

        Publishes the agent's identity, capabilities, domains, and
        endpoints to the Agent Registry.

        Returns:
            Registry response dict.
        """
        assert self._identity is not None
        assert self._registry is not None

        caps = [
            {"id": f"cap:{c}", "name": c, "version": "1.0"}
            for c in self.capabilities
        ]

        endpoints: list[dict[str, Any]] = []
        if self.service_endpoint:
            t_type = "ocp-ws" if "ws" in self.service_endpoint else "ocp-http"
            endpoints.append({
                "transport": t_type,
                "url": self.service_endpoint,
                "priority": 1,
            })

        record = AgentRecord(
            agent_id=self.agent_id,
            display_name=self.name,
            capabilities=caps,
            domains=self.domains,
            endpoints=endpoints,
        )

        sig_data = f"register:{self.agent_id}".encode()
        sig = self._identity.signing_keys.sign(sig_data)
        result = await self._registry.register(record, b64url_encode(sig))
        logger.info("Registered on network: %s", self.agent_id)
        return result

    # ---- Discovery ----

    async def discover(
        self,
        domain: str | None = None,
        capability: str | None = None,
        min_trust_level: int = 0,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Discover peer agents by domain and/or capability.

        Args:
            domain: Filter by domain.
            capability: Filter by capability.
            min_trust_level: Minimum trust level.
            limit: Maximum results.

        Returns:
            List of matching agent record dicts.
        """
        assert self._registry is not None
        results = await self._registry.discover(
            domains=[domain] if domain else None,
            capabilities=[capability] if capability else None,
            min_trust_level=min_trust_level,
            limit=limit,
        )
        logger.info("Discovered %d peers", len(results))
        return results

    # ---- Messaging ----

    def _builder(self) -> MessageBuilder:
        """Create a MessageBuilder pre-configured with this agent's identity."""
        assert self._identity is not None
        return MessageBuilder(self.agent_id, self._identity.signing_keys)

    async def send_message(
        self,
        to: str,
        msg_type: MessageType,
        payload: dict[str, Any],
        priority: Priority = Priority.NORMAL,
        require_ack: bool = False,
    ) -> dict[str, Any]:
        """Send a message to another agent.

        Args:
            to: Receiver's DID.
            msg_type: The message type.
            payload: Message payload.
            priority: Message priority.
            require_ack: Whether to request acknowledgement.

        Returns:
            Transport response dict.

        Raises:
            OCPValidationError: If no transport is configured.
        """
        builder = self._builder().to(to).type(msg_type).payload(payload).priority(priority)
        if require_ack:
            builder.require_ack()
        msg = builder.build()

        if self._http_transport:
            return await self._http_transport.send(msg)
        if self._ws_transport and self._ws_transport.is_connected:
            await self._ws_transport.send(msg)
            return {}

        raise OCPValidationError(
            "No transport configured. Call connect_ws() or connect_http() first.",
            code="OCP-500",
        )

    async def broadcast(self, payload: dict[str, Any], tags: list[str] | None = None) -> dict[str, Any]:
        """Broadcast a message to all agents matching the given tags.

        Args:
            payload: Message payload.
            tags: Domain/topic tags for broadcast routing.

        Returns:
            Transport response dict.
        """
        builder = (
            self._builder()
            .to_broadcast()
            .type(MessageType.BROADCAST)
            .payload(payload)
        )
        if tags:
            builder.tag(*tags)
        msg = builder.build()

        if self._http_transport:
            return await self._http_transport.send(msg)
        raise OCPValidationError("No transport configured", code="OCP-500")

    # ---- Knowledge Sharing ----

    async def share(
        self,
        knowledge: InsightPackage | EmbeddingPackage | ModelDelta,
        to: str,
    ) -> dict[str, Any]:
        """Share knowledge with a peer agent.

        Enforces the Privacy Validation Layer and checks bond permissions
        before sending.

        Args:
            knowledge: The knowledge to share.
            to: Receiver's DID.

        Returns:
            Transport response dict.

        Raises:
            OCPPrivacyViolation: If the payload fails PVL checks.
            OCPTrustError: If the bond doesn't permit the knowledge type.
        """
        payload = knowledge.to_payload()
        enforce_pvl(payload)

        bond = self._bonds.get(to)
        if bond and bond.is_active:
            k_type = payload.get("knowledge_type", "")
            if not bond.permits_knowledge_share(k_type):
                raise OCPTrustError(
                    f"Bond with {to} does not permit sharing '{k_type}'",
                    code="OCP-403",
                )

        return await self.send_message(to, MessageType.KNOWLEDGE_SHARE, payload)

    # ---- Bonding ----

    async def request_bond(
        self,
        peer_id: str,
        permissions: BondPermissions | None = None,
        duration_days: int = 180,
    ) -> dict[str, Any]:
        """Send a bond request to a peer agent.

        Args:
            peer_id: The peer's DID.
            permissions: Proposed permissions.
            duration_days: Proposed bond duration.

        Returns:
            Transport response dict.
        """
        perms = permissions or BondPermissions()
        payload = {
            "proposed_permissions": perms.to_dict(),
            "proposed_duration_days": duration_days,
        }
        return await self.send_message(
            peer_id, MessageType.BOND_REQUEST, payload, require_ack=True
        )

    def accept_bond(self, peer_id: str, bond: Bond) -> None:
        """Record an accepted bond locally.

        Args:
            peer_id: The bonded peer's DID.
            bond: The accepted bond.
        """
        self._bonds[peer_id] = bond
        logger.info("Bond accepted with %s: %s", peer_id, bond.bond_id)

    def revoke_bond(self, peer_id: str) -> Bond | None:
        """Revoke a bond with a peer.

        Args:
            peer_id: The peer's DID.

        Returns:
            The revoked bond, or ``None`` if no bond existed.
        """
        bond = self._bonds.get(peer_id)
        if bond:
            bond.revoke(self.agent_id)
            logger.info("Bond revoked with %s: %s", peer_id, bond.bond_id)
        return bond

    # ---- Vouching ----

    def vouch_for(self, subject_id: str, domains: list[str]) -> Vouch:
        """Create a signed vouch for another agent.

        Args:
            subject_id: The DID of the agent to vouch for.
            domains: Domains the vouch covers.

        Returns:
            A signed :class:`Vouch`.
        """
        assert self._identity is not None
        vouch = Vouch(
            attester_id=self.agent_id,
            subject_id=subject_id,
            domains=domains,
            signing_keys=self._identity.signing_keys,
        )
        self._vouches_given.append(vouch)
        logger.info("Vouched for %s in domains %s", subject_id, domains)
        return vouch

    def receive_vouch(self, vouch: Vouch) -> None:
        """Record a received vouch.

        Args:
            vouch: The received vouch.
        """
        self._vouches_received.append(vouch)

    # ---- Task Delegation ----

    async def delegate_task(
        self,
        to: str,
        task_type: str,
        description: str,
        input_data: dict[str, Any],
        max_duration: int = 300,
        required_capabilities: list[str] | None = None,
    ) -> dict[str, Any]:
        """Delegate a task to a bonded peer.

        Args:
            to: Receiver's DID.
            task_type: Task category.
            description: Human-readable task description.
            input_data: Task input.
            max_duration: Maximum duration in seconds.
            required_capabilities: Capabilities the receiver must have.

        Returns:
            Transport response dict.

        Raises:
            OCPTrustError: If the bond doesn't permit task delegation.
        """
        bond = self._bonds.get(to)
        if bond and not bond.permits_task_delegation():
            raise OCPTrustError(
                f"Bond with {to} does not permit task delegation",
                code="OCP-403",
            )

        payload = {
            "task_id": generate_uuid_short("task-"),
            "task_type": task_type,
            "description": description,
            "input": {"format": "application/json", "data": input_data},
            "constraints": {
                "max_duration_seconds": max_duration,
                "required_capabilities": required_capabilities or [],
                "min_trust_level": 0,
            },
            "callback": {
                "type": "ocp_message",
                "agent_id": self.agent_id,
            },
        }
        return await self.send_message(to, MessageType.TASK_REQUEST, payload)

    # ---- Consensus ----

    def initiate_consensus(self, config: ConsensusConfig) -> ConsensusRound:
        """Create a new consensus round.

        Args:
            config: Consensus configuration.

        Returns:
            A new :class:`ConsensusRound`.
        """
        cr = ConsensusRound(config)
        self._active_consensus[cr.consensus_id] = cr
        logger.info("Consensus initiated: %s — %s", cr.consensus_id, config.topic)
        return cr

    # ---- Connection Management ----

    async def connect_ws(self, url: str | None = None) -> None:
        """Establish a WebSocket connection.

        Args:
            url: WebSocket URL. Uses ``service_endpoint`` if not provided.
        """
        assert self._identity is not None
        target = url or self.service_endpoint
        if not target:
            raise OCPValidationError("No WebSocket URL provided", code="OCP-500")
        config = TransportConfig(url=target, transport_type="ocp-ws")
        self._ws_transport = WebSocketTransport(
            config, self.agent_id, self._identity.signing_keys
        )
        await self._ws_transport.connect()

    async def connect_http(self, url: str | None = None) -> None:
        """Configure HTTP transport.

        Args:
            url: HTTPS endpoint URL. Uses ``service_endpoint`` if not provided.
        """
        assert self._identity is not None
        target = url or self.service_endpoint
        if not target:
            raise OCPValidationError("No HTTP URL provided", code="OCP-500")
        config = TransportConfig(url=target, transport_type="ocp-http")
        self._http_transport = HTTPTransport(
            config, self.agent_id, self._identity.signing_keys
        )

    async def close(self) -> None:
        """Close all transports and the registry client."""
        if self._ws_transport:
            await self._ws_transport.close()
        if self._http_transport:
            await self._http_transport.close()
        if self._registry:
            await self._registry.close()
        logger.info("Agent closed: %s", self.agent_id)
