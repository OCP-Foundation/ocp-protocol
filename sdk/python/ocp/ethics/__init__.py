"""OCP Ethics Module — Complete ethics enforcement for the OpenCognition Protocol.

Implements OCP Ethics Bible v2.1 Final + all 52 integration changes.

28 modules covering every INT-001 through INT-052.
"""

# Core infrastructure
from .evl import EVL, EVLResult
from .eal import EAL, EALEntry
from .pur import PUR, PUREntry

# Subsystems (v2.0)
from .consent import ConsentManager, ConsentToken
from .risk_classification import RiskClassifier, RiskTier
from .bias import BiasValidator, BiasDisclosure
from .transparency import TransparencyCard
from .decommission import DecommissionManager
from .trust_anti_gaming import TrustAntiGaming
from .consensus_integrity import ConsensusIntegrityChecker
from .message_ethics import EthicsMetadataBuilder, EthicsMetadataValidator
from .agent_record_ext import AgentRecordEthicsExtension
from .did_ext import DIDDocumentEthicsExtension
from .compute_footprint import ComputeFootprint, ComputeFootprintTracker
from .data_sovereignty import DataSovereigntyEnforcer
from .knowledge_expiry import KnowledgeExpiryChecker
from .training_provenance import TrainingProvenanceValidator
from .compliance_checker import EthicalComplianceChecker, ComplianceResult
from .bond_ethics import BondEthicsExtension

# Subsystems (v2.1)
from .synthetic import SyntheticContentLabeler, SyntheticLabel
from .cascade import CascadeCircuitBreaker, CascadeEvent
from .sanctions import SanctionsScreener, SanctionsResult
from .notifications import NotificationManager, Notification
from .dual_use import DualUseClassifier, DualUseLevel
from .power_dynamics import PowerDynamicsMonitor
from .cognitive import CognitiveDataProtector
from .model_collapse import ModelCollapsePreventor
from .emergent_behavior import EmergentBehaviorDetector

__version__ = "2.1.0"

