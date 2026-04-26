"""Transport layer — WebSocket and HTTPS transports.

OCP supports multiple transport mechanisms. This module implements the
two most common:

- **WebSocket** (``ocp-ws``): Real-time bidirectional, recommended for
  persistent connections.
- **HTTPS** (``ocp-http``): Request-response, firewall-friendly.

Both transports enforce TLS and implement the OCP authentication
handshake or header scheme.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable

import httpx
import websockets
from websockets.asyncio.client import ClientConnection

from ocp.constants import (
    AUTH_HANDSHAKE_TIMEOUT,
    MAX_RETRY_COUNT,
    RETRY_BASE_DELAY,
    WS_SUBPROTOCOL,
)
from ocp.crypto import SigningKeyPair, b64url_encode, generate_nonce, sha3_256
from ocp.exceptions import (
    OCPAuthError,
    OCPRateLimitError,
    OCPTimeoutError,
    OCPTransportError,
)

logger = logging.getLogger("ocp.transport")


@dataclass
class TransportConfig:
    """Configuration for an OCP transport.

    Attributes:
        url: Endpoint URL.
        transport_type: Transport identifier (``"ocp-ws"`` or ``"ocp-http"``).
        connect_timeout: Connection timeout in seconds.
        request_timeout: Per-request timeout in seconds.
        max_retries: Maximum retry count on delivery failure.
        retry_base_delay: Base delay for exponential backoff.
    """

    url: str
    transport_type: str = "ocp-ws"
    connect_timeout: float = 10.0
    request_timeout: float = 30.0
    max_retries: int = MAX_RETRY_COUNT
    retry_base_delay: float = RETRY_BASE_DELAY


# ==========================================================================
# WebSocket transport
# ==========================================================================

class WebSocketTransport:
    """OCP WebSocket transport (``ocp-ws``).

    Provides real-time bidirectional communication with auth handshake,
    message send/receive, and automatic reconnection.

    Args:
        config: Transport configuration.
        agent_id: The agent's DID.
        signing_keys: The agent's Ed25519 keypair.
    """

    def __init__(
        self,
        config: TransportConfig,
        agent_id: str,
        signing_keys: SigningKeyPair,
    ) -> None:
        self._config = config
        self._agent_id = agent_id
        self._signing_keys = signing_keys
        self._conn: ClientConnection | None = None
        self._session_id: str | None = None
        self._connected: bool = False
        self._message_handlers: list[Callable[[dict[str, Any]], Any]] = []

    @property
    def is_connected(self) -> bool:
        """Whether the transport has an active connection."""
        return self._connected and self._conn is not None

    @property
    def session_id(self) -> str | None:
        """The current session ID, or ``None`` if not connected."""
        return self._session_id

    async def connect(self) -> None:
        """Establish WebSocket connection and perform auth handshake.

        Raises:
            OCPTransportError: If the connection fails.
            OCPAuthError: If the auth handshake is rejected.
        """
        try:
            self._conn = await websockets.connect(
                self._config.url,
                subprotocols=[WS_SUBPROTOCOL],
                open_timeout=self._config.connect_timeout,
            )
            logger.info("WebSocket connected to %s", self._config.url)
        except Exception as e:
            raise OCPTransportError(
                f"WebSocket connection failed: {e}", code="OCP-502"
            )

        # Auth handshake
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = generate_nonce()
        sign_data = f"{self._agent_id}||{ts}||{nonce}".encode()
        sig = self._signing_keys.sign(sha3_256(sign_data))

        handshake = {
            "frame_type": "auth_handshake",
            "agent_id": self._agent_id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": b64url_encode(sig),
        }
        await self._conn.send(json.dumps(handshake))

        try:
            raw = await asyncio.wait_for(
                self._conn.recv(),
                timeout=AUTH_HANDSHAKE_TIMEOUT,
            )
            result = json.loads(raw)

            if result.get("status") != "accepted":
                reason = result.get("reason", "unknown")
                raise OCPAuthError(f"Auth rejected: {reason}", code="OCP-401")

            self._session_id = result.get("session_id")
            self._connected = True
            logger.info("Auth handshake accepted, session=%s", self._session_id)

        except asyncio.TimeoutError:
            await self._conn.close()
            raise OCPTimeoutError("Auth handshake timed out")
        except OCPAuthError:
            await self._conn.close()
            raise
        except Exception as e:
            await self._conn.close()
            raise OCPAuthError(f"Auth handshake failed: {e}", code="OCP-401")

    async def send(self, message: dict[str, Any]) -> None:
        """Send an OCPUMF message over the WebSocket.

        Args:
            message: A signed OCPUMF message dict.

        Raises:
            OCPTransportError: If not connected or send fails.
        """
        if not self.is_connected:
            raise OCPTransportError("Not connected", code="OCP-500")
        try:
            await self._conn.send(json.dumps(message))  # type: ignore
        except Exception as e:
            self._connected = False
            raise OCPTransportError(f"Send failed: {e}", code="OCP-502")

    async def receive(self) -> dict[str, Any]:
        """Receive a single OCPUMF message.

        Returns:
            Parsed OCPUMF message dict.

        Raises:
            OCPTransportError: If not connected or receive fails.
        """
        if not self.is_connected:
            raise OCPTransportError("Not connected", code="OCP-500")
        try:
            raw = await self._conn.recv()  # type: ignore
            return json.loads(raw)
        except Exception as e:
            self._connected = False
            raise OCPTransportError(f"Receive failed: {e}", code="OCP-502")

    async def listen(self) -> AsyncIterator[dict[str, Any]]:
        """Async iterator over incoming messages.

        Yields:
            Parsed OCPUMF message dicts.
        """
        if not self.is_connected:
            raise OCPTransportError("Not connected", code="OCP-500")
        try:
            async for raw in self._conn:  # type: ignore
                msg = json.loads(raw)
                yield msg
        except websockets.exceptions.ConnectionClosed:
            self._connected = False
            logger.warning("WebSocket connection closed")

    def on_message(self, handler: Callable[[dict[str, Any]], Any]) -> None:
        """Register a message handler callback.

        Args:
            handler: Callable that receives a parsed OCPUMF message dict.
        """
        self._message_handlers.append(handler)

    async def close(self) -> None:
        """Close the WebSocket connection."""
        self._connected = False
        if self._conn:
            try:
                await self._conn.close()
            except Exception:
                pass
            self._conn = None
        logger.info("WebSocket transport closed")


# ==========================================================================
# HTTPS transport
# ==========================================================================

class HTTPTransport:
    """OCP HTTPS transport (``ocp-http``).

    Provides request-response communication with the ``OCP-Ed25519``
    authorization header scheme.

    Args:
        config: Transport configuration.
        agent_id: The agent's DID.
        signing_keys: The agent's Ed25519 keypair.
    """

    def __init__(
        self,
        config: TransportConfig,
        agent_id: str,
        signing_keys: SigningKeyPair,
    ) -> None:
        self._config = config
        self._agent_id = agent_id
        self._signing_keys = signing_keys
        self._client = httpx.AsyncClient(
            timeout=config.request_timeout,
            http2=True,
        )

    def _auth_header(self) -> str:
        """Generate the ``OCP-Ed25519`` authorization header value."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sign_data = f"{self._agent_id}||{ts}".encode()
        sig = self._signing_keys.sign(sha3_256(sign_data))
        return f"OCP-Ed25519 {self._agent_id}:{ts}:{b64url_encode(sig)}"

    async def send(
        self,
        message: dict[str, Any],
        retry: bool = True,
    ) -> dict[str, Any]:
        """Send a message via HTTPS POST.

        Args:
            message: A signed OCPUMF message dict.
            retry: Whether to retry on transient failures.

        Returns:
            Response body as dict (empty dict for 202 Accepted).

        Raises:
            OCPRateLimitError: If rate-limited (429).
            OCPTransportError: On other HTTP errors.
        """
        last_error: Exception | None = None
        attempts = self._config.max_retries if retry else 1

        for attempt in range(attempts):
            try:
                resp = await self._client.post(
                    self._config.url,
                    json=message,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": self._auth_header(),
                        "X-OCP-Version": "1.0",
                    },
                )

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "60"))
                    raise OCPRateLimitError("Rate limited", retry_after=retry_after)

                if resp.status_code == 202:
                    return {}

                if resp.status_code >= 400:
                    raise OCPTransportError(
                        f"HTTP {resp.status_code}: {resp.text}",
                        code=f"OCP-{resp.status_code}",
                    )

                return resp.json() if resp.text else {}

            except (OCPRateLimitError, OCPTransportError):
                raise
            except Exception as e:
                last_error = e
                if attempt < attempts - 1:
                    delay = self._config.retry_base_delay * (2 ** attempt)
                    logger.warning(
                        "HTTP attempt %d failed (%s), retrying in %.1fs",
                        attempt + 1, e, delay,
                    )
                    await asyncio.sleep(delay)

        raise OCPTransportError(
            f"HTTP request failed after {attempts} attempts: {last_error}",
            code="OCP-502",
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
        logger.info("HTTP transport closed")
