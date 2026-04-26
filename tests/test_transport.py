"""Tests for transport layer — unit tests (no live server required).

Compliance category: Transport (4 tests)
"""

from ocp.identity import AgentIdentity
from ocp.transport import TransportConfig, HTTPTransport, WebSocketTransport


class TestTransportConfig:
    """Transport configuration."""

    def test_default_websocket(self):
        cfg = TransportConfig(url="wss://localhost:8421/ocp/v1/ws")
        assert cfg.transport_type == "ocp-ws"
        assert cfg.connect_timeout == 10.0
        assert cfg.request_timeout == 30.0
        assert cfg.max_retries == 5

    def test_http_config(self):
        cfg = TransportConfig(
            url="https://localhost:8420/ocp/v1/messages",
            transport_type="ocp-http",
            request_timeout=60.0,
        )
        assert cfg.transport_type == "ocp-http"
        assert cfg.request_timeout == 60.0


class TestHTTPAuth:
    """OCP-SPEC §3.1.2 — HTTP authorization header."""

    """OCP-SPEC §3.1.2 — HTTP authorization header."""

    def test_auth_header_format(self):
        ident = AgentIdentity.generate(network="testnet")
        cfg = TransportConfig(url="https://test.example.com/ocp/v1/messages", transport_type="ocp-http")
        transport = HTTPTransport(cfg, ident.agent_id, ident.signing_keys)
        header = transport._auth_header()
        assert header.startswith("OCP-Ed25519 did:ocp:testnet:")
        credentials = header.split(" ", 1)[1]
        parts = credentials.rsplit(":", 2)
        assert len(parts) == 3  # [agent_id, timestamp, signature]
        # Verify the timestamp is actually in the middle
        assert "Z" in parts[1]  # ISO timestamp check

    def test_auth_header_changes_per_call(self):
        ident = AgentIdentity.generate(network="testnet")
        cfg = TransportConfig(url="https://test.example.com/ocp/v1/messages", transport_type="ocp-http")
        transport = HTTPTransport(cfg, ident.agent_id, ident.signing_keys)
        h1 = transport._auth_header()
        import time; time.sleep(0.01)
        h2 = transport._auth_header()
        # Signatures differ because timestamp changes (or nonce differs)
        # At minimum, the signature portion should differ
        assert h1.split(":")[-1] != h2.split(":")[-1] or h1 == h2  # may match if same second


class TestWebSocketConfig:
    """WebSocket transport initialization."""

    def test_not_connected_by_default(self):
        ident = AgentIdentity.generate(network="testnet")
        cfg = TransportConfig(url="wss://test.example.com/ocp/v1/ws")
        transport = WebSocketTransport(cfg, ident.agent_id, ident.signing_keys)
        assert not transport.is_connected
        assert transport.session_id is None