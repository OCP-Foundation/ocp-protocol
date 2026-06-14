"""OpenCognition Protocol (OCP) — Python SDK.

A reference implementation of the OCP protocol for building AI agents
that can discover, trust, and collaborate with peer agents across
organizational and platform boundaries.

Basic usage::

    from ocp import Agent

    agent = Agent(
        name="MyAI",
        capabilities=["nlp:classification"],
        domains=["finance"],
    )
    await agent.register()
    peers = await agent.discover(domain="finance")
    await agent.share(insight, to=peers[0]["agent_id"])
"""

__version__ = "1.0.0"
__ocp_version__ = "1.0"
__all__ = [
    # Core
    "Agent",
    # Identity
    "AgentIdentity",
    "DIDDocument",
    # Messages
    "MessageBuilder",
    "MessageType",
    "MessageValidator",
    "Priority",
    # Knowledge
    "EmbeddingPackage",
    "EmbeddingVector",
    "InsightPackage",
    "InsightFeature",
    "ModelDelta",
    # Trust
    "Bond",
    "BondPermissions",
    "TrustLevel",
    "TrustScoreWeights",
    "Vouch",
    "compute_trust_score",
    # Recovery
    "RecoveryManager",
    "RecoveryShare",
    "split_secret",
    "reconstruct_secret",
    # Transport
    "WebSocketTransport",
    "HTTPTransport",
    "TransportConfig",
    # Registry
    "RegistryClient",
    "RegistryConfig",
    "AgentRecord",
    # Privacy
    "validate_knowledge_payload",
    "enforce_pvl",
    "PVLResult",
    # Consensus
    "ConsensusConfig",
    "ConsensusRound",
    "ConsensusResult",
    "Vote",
    # Ethics Framework Submodule Namespace
    "ethics",
    # Primary Ethics Exports (Brought to root level for ease of use)
    "EVL",
    "EthicalComplianceChecker",
    "PUR",
    # Exceptions
    "OCPError",
    "OCPAuthError",
    "OCPTransportError",
    "OCPValidationError",
    "OCPTrustError",
    "OCPPrivacyViolation",
    "OCPTimeoutError",
    "OCPRateLimitError",
    "OCPAgentNotFoundError",
]

from ocp.agent import Agent
from ocp.consensus import ConsensusConfig, ConsensusRound, ConsensusResult, Vote
from ocp.exceptions import (
    OCPError,
    OCPAuthError,
    OCPTransportError,
    OCPValidationError,
    OCPTrustError,
    OCPPrivacyViolation,
    OCPTimeoutError,
    OCPRateLimitError,
    OCPAgentNotFoundError,
)
from ocp.identity import AgentIdentity, DIDDocument
from ocp.knowledge import (
    EmbeddingPackage,
    EmbeddingVector,
    InsightPackage,
    InsightFeature,
    ModelDelta,
)
from ocp.messages import MessageBuilder, MessageType, MessageValidator, Priority
from ocp.pvl import validate_knowledge_payload, enforce_pvl, PVLResult
from ocp.recovery import RecoveryManager, RecoveryShare, split_secret, reconstruct_secret
from ocp.registry import RegistryClient, RegistryConfig, AgentRecord
from ocp.transport import WebSocketTransport, HTTPTransport, TransportConfig
from ocp.trust import (
    Bond,
    BondPermissions,
    TrustLevel,
    TrustScoreWeights,
    Vouch,
    compute_trust_score,
)

# --- ⚖️ Integrated Ethics Framework Sub-Package ---
from ocp import ethics
from ocp.ethics.evl import EVL
from ocp.ethics.compliance_checker import EthicalComplianceChecker
from ocp.ethics.pur import PUR
