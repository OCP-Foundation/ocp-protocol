"""Agent Registry client.

Provides methods for agent registration, peer discovery, and DID
resolution against an OCP Agent Registry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ocp.constants import REGISTRY_RECORD_DEFAULT_TTL
from ocp.exceptions import OCPAgentNotFoundError, OCPTransportError

logger = logging.getLogger("ocp.registry")


@dataclass
class RegistryConfig:
    """Registry client configuration.

    Attributes:
        base_url: Base URL of the registry API.
        timeout: HTTP request timeout in seconds.
    """

    base_url: str = "https://registry.opencognitionprotocol.org/ocp/v1"
    timeout: float = 15.0


@dataclass
class AgentRecord:
    """An agent's registry record.

    Attributes:
        agent_id: The agent's DID.
        display_name: Human-readable name.
        capabilities: List of capability dicts.
        domains: List of domain identifiers.
        endpoints: List of endpoint dicts.
        trust_level: Current trust level (0–4).
        version: Agent software version.
        status: Registration status.
        extensions: Supported OCP extensions.
    """

    agent_id: str
    display_name: str
    capabilities: list[dict[str, Any]]
    domains: list[str]
    endpoints: list[dict[str, Any]]
    trust_level: int = 0
    version: str = "1.0.0"
    status: str = "active"
    extensions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a registry record dict."""
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "version": self.version,
            "capabilities": self.capabilities,
            "domains": self.domains,
            "endpoints": self.endpoints,
            "trust_level": self.trust_level,
            "status": self.status,
            "extensions": self.extensions,
            "ttl": REGISTRY_RECORD_DEFAULT_TTL,
        }


class RegistryClient:
    """Client for the OCP Agent Registry.

    Handles agent registration, peer discovery, and DID resolution.

    Args:
        config: Registry configuration. Uses defaults if ``None``.
    """

    def __init__(self, config: RegistryConfig | None = None) -> None:
        self._config = config or RegistryConfig()
        self._client = httpx.AsyncClient(
            timeout=self._config.timeout,
            http2=True,
        )

    async def register(self, record: AgentRecord, signature: str) -> dict[str, Any]:
        """Register or update an agent record.

        Args:
            record: The agent record to register.
            signature: Base64url Ed25519 signature over the record.

        Returns:
            Registry response dict.

        Raises:
            OCPTransportError: If registration fails.
        """
        payload = record.to_dict()
        payload["signature"] = signature

        try:
            resp = await self._client.post(
                f"{self._config.base_url}/registry/agents",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise OCPTransportError(
                f"Registration failed: {e.response.status_code} {e.response.text}",
                code="OCP-500",
            )
        except httpx.RequestError as e:
            raise OCPTransportError(f"Registration request failed: {e}", code="OCP-502")

    async def discover(
        self,
        domains: list[str] | None = None,
        capabilities: list[str] | None = None,
        min_trust_level: int = 0,
        status: str = "active",
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Discover agents by domain, capability, and trust level.

        Args:
            domains: Filter by domain(s).
            capabilities: Filter by capability ID(s).
            min_trust_level: Minimum required trust level.
            status: Agent status filter (default ``"active"``).
            limit: Maximum results to return.
            offset: Pagination offset.

        Returns:
            List of matching agent record dicts.
        """
        filters: dict[str, Any] = {"status": status}
        if domains:
            filters["domains"] = domains
        if capabilities:
            filters["capabilities"] = capabilities
        if min_trust_level > 0:
            filters["min_trust_level"] = min_trust_level

        try:
            resp = await self._client.post(
                f"{self._config.base_url}/registry/discover",
                json={"filters": filters, "limit": limit, "offset": offset},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("results", [])
        except httpx.HTTPStatusError as e:
            raise OCPTransportError(
                f"Discovery failed: {e.response.status_code}",
                code="OCP-500",
            )
        except httpx.RequestError as e:
            raise OCPTransportError(f"Discovery request failed: {e}", code="OCP-502")

    async def resolve(self, agent_id: str) -> dict[str, Any]:
        """Resolve an agent ID to its full record.

        Args:
            agent_id: The agent's DID.

        Returns:
            Full agent record dict.

        Raises:
            OCPAgentNotFoundError: If the agent doesn't exist.
            OCPTransportError: On other failures.
        """
        try:
            resp = await self._client.get(
                f"{self._config.base_url}/registry/agents/{agent_id}",
            )
            if resp.status_code == 404:
                raise OCPAgentNotFoundError(f"Agent not found: {agent_id}")
            resp.raise_for_status()
            return resp.json()
        except OCPAgentNotFoundError:
            raise
        except httpx.HTTPStatusError as e:
            raise OCPTransportError(
                f"Resolution failed: {e.response.status_code}",
                code="OCP-500",
            )
        except httpx.RequestError as e:
            raise OCPTransportError(f"Resolution request failed: {e}", code="OCP-502")

    async def deregister(self, agent_id: str, signature: str) -> dict[str, Any]:
        """Remove an agent from the registry.

        Args:
            agent_id: The agent's DID.
            signature: Auth signature.

        Returns:
            Registry response dict.
        """
        try:
            resp = await self._client.delete(
                f"{self._config.base_url}/registry/agents/{agent_id}",
                headers={"Authorization": f"OCP-Ed25519 {signature}"},
            )
            resp.raise_for_status()
            return resp.json() if resp.text else {}
        except httpx.HTTPStatusError as e:
            raise OCPTransportError(
                f"Deregistration failed: {e.response.status_code}",
                code="OCP-500",
            )

    async def close(self) -> None:
        """Close the registry client."""
        await self._client.aclose()
