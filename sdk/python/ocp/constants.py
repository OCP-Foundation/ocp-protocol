"""Protocol-level constants defined by the OCP v1.0 specification.

These values are normative. Changing them produces a non-conforming
implementation unless the spec itself is revised.
"""

from __future__ import annotations

# --- Protocol version ---
OCP_VERSION: str = "1.0"

# --- Size limits ---
MAX_MESSAGE_SIZE: int = 16_777_216       # 16 MB
MAX_PAYLOAD_SIZE: int = 10_485_760       # 10 MB

# --- Time-to-live ---
DEFAULT_TTL: int = 3600                  # 1 hour
MAX_TTL: int = 86_400                    # 24 hours

# --- Timeouts ---
AUTH_HANDSHAKE_TIMEOUT: float = 5.0      # seconds
ACK_TIMEOUT: float = 30.0               # seconds
TASK_DEFAULT_TIMEOUT: int = 300          # seconds

# --- Retry ---
MAX_RETRY_COUNT: int = 5
RETRY_BASE_DELAY: float = 1.0           # seconds, exponential backoff

# --- Registry ---
REGISTRY_RECORD_DEFAULT_TTL: int = 86_400  # 24 hours

# --- Trust ---
MAX_VOUCH_DURATION_SECONDS: int = 31_536_000   # 365 days
MAX_BOND_DURATION_SECONDS: int = 31_536_000    # 365 days

# --- Crypto ---
KEY_ROTATION_RECOMMENDED_SECONDS: int = 7_776_000  # 90 days

# --- Trust score ---
TRUST_SCORE_MIN: float = 0.0
TRUST_SCORE_MAX: float = 1.0

# --- Differential privacy ---
MAX_EPSILON: float = 10.0

# --- Rate limits (defaults) ---
RATE_MESSAGES_PER_MINUTE: int = 1000
RATE_BOND_REQUESTS_PER_HOUR: int = 10
RATE_DISCOVERY_PER_MINUTE: int = 100
RATE_BROADCAST_PER_MINUTE: int = 5
RATE_KNOWLEDGE_PER_MINUTE: int = 50

# --- Recovery ---
DEFAULT_RECOVERY_THRESHOLD: int = 3
DEFAULT_RECOVERY_SHARES: int = 5
MAX_RECOVERY_SHARES: int = 255

# --- Supported transports ---
TRANSPORT_WS: str = "ocp-ws"
TRANSPORT_HTTP: str = "ocp-http"
TRANSPORT_NATS: str = "ocp-nats"
TRANSPORT_GRPC: str = "ocp-grpc"

SUPPORTED_TRANSPORTS: frozenset[str] = frozenset(
    {TRANSPORT_WS, TRANSPORT_HTTP, TRANSPORT_NATS, TRANSPORT_GRPC}
)

# --- Network identifiers ---
NETWORK_MAINNET: str = "mainnet"
NETWORK_TESTNET: str = "testnet"

# --- DID method ---
DID_METHOD: str = "ocp"

# --- WebSocket subprotocol ---
WS_SUBPROTOCOL: str = "ocp.v1"

# --- HKDF info strings ---
HKDF_INFO_AES_KEY: bytes = b"ocp-v1-aes-key"
HKDF_INFO_RECOVERY: bytes = b"ocp-v1-recovery-share"


