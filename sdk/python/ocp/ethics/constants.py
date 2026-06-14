"""
Ethics constants — EVL codes, risk tiers, thresholds, SLAs.
Ref: OCP Ethics Bible v2.1 §35, §4, Appendix K
"""
from enum import Enum

class EVLCode(str, Enum):
    """Ethics Validation Layer rejection codes."""
    EVL_001 = "EVL-001"  # Identity inference without consent
    EVL_002 = "EVL-002"  # Market manipulation pattern
    EVL_003 = "EVL-003"  # Unauthorized health/genomic data
    EVL_004 = "EVL-004"  # Anticompetitive coordination
    EVL_005 = "EVL-005"  # Adversarially crafted signal
    EVL_006 = "EVL-006"  # Lethal automation — no human approval
    EVL_007 = "EVL-007"  # Missing consent token
    EVL_008 = "EVL-008"  # Irreversible action requires HITL
    EVL_009 = "EVL-009"  # Child/vulnerable safeguard missing
    EVL_010 = "EVL-010"  # Social scoring pattern
    EVL_011 = "EVL-011"  # Synthetic content label missing
    EVL_012 = "EVL-012"  # Cascade circuit breaker triggered

class RiskTier(str, Enum):
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"

class DualUseLevel(str, Enum):
    NO_CONCERN = "no_dual_use_concern"
    AWARE = "dual_use_aware"
    RESTRICTED = "dual_use_restricted"

class ConsentBasis(str, Enum):
    IRB_APPROVAL = "irb_approval"
    PATIENT_CONSENT = "patient_consent"
    PARENTAL_CONSENT = "parental_consent"
    REGULATORY_MANDATE = "regulatory_mandate"
    LEGITIMATE_INTEREST = "legitimate_interest"
    PUBLIC_INTEREST = "public_interest"
    INDIGENOUS_CONSENT = "indigenous_consent"
    EXPLICIT_INDIVIDUAL = "explicit_individual_consent"
    EXPLICIT_COGNITIVE = "explicit_cognitive_consent"

class Severity(str, Enum):
    CRITICAL = "critical"   # 1 hour response
    HIGH = "high"           # 24 hours
    MEDIUM = "medium"       # 72 hours
    LOW = "low"             # 14 days

class HITLLevel(str, Enum):
    ADVISORY = "advisory"
    REVIEW = "review"
    APPROVAL = "approval"
    VETO = "veto"

# Regulated domains requiring consent tokens
REGULATED_DOMAINS = frozenset([
    "healthcare", "healthcare.oncology", "healthcare.cardiology",
    "healthcare.radiology", "healthcare.genomics", "healthcare.pharmacology",
    "healthcare.mental_health", "finance.credit", "legal",
    "legal.contract_analysis", "legal.compliance", "legal.litigation",
    "education.assessment",
])

# Physical actuator domains requiring HITL for autonomous execution
PHYSICAL_ACTUATOR_DOMAINS = frozenset([
    "robotics", "infrastructure", "medical_device", "defense",
])

# Dual-use domains
DUAL_USE_DOMAINS = frozenset([
    "cybersecurity", "virology", "chemistry", "materials_science",
    "nuclear_physics", "ai_safety_research",
])

# Unacceptable capabilities (always blocked)
UNACCEPTABLE_CAPABILITIES = frozenset([
    "cap:custom:*:lethal_force",
    "cap:custom:*:surveillance",
    "cap:custom:*:social_scoring",
])

# Thresholds
CASCADE_THRESHOLD_AGENTS = 50
CASCADE_THRESHOLD_HOURS = 24
CASCADE_PAUSE_MINUTES = 60
MODEL_COLLAPSE_MAX_GENERATION = 3
OCP_SOURCE_RATIO_MAX = 0.6
FEEDBACK_SIMILARITY_THRESHOLD = 0.95
TRUST_SCORE_ANOMALY_THRESHOLD = 0.3
TRUST_SCORE_ANOMALY_DAYS = 30
VOUCH_TRADING_WINDOW_HOURS = 48
VOUCH_TRADING_FLAG_THRESHOLD = 3
SAME_ORG_VOTE_WINDOW_SECONDS = 60
SAME_ORG_VOTE_WEIGHT = 0.5
EXPLOITATIVE_DELEGATION_THRESHOLD = 5
EXPLOITATIVE_DELEGATION_DAYS = 30
CONCENTRATION_LIMIT_PERCENT = 30
MAX_EPSILON = 10.0
SENSITIVE_DOMAIN_EPSILON = 1.0
COGNITIVE_DATA_EPSILON = 1.0

# SLA deadlines (seconds)
SLA_ETHICS_CONTACT_RESPONSE = 48 * 3600      # 48 hours
SLA_CONSENT_WITHDRAWAL = 72 * 3600            # 72 hours
SLA_FEEDBACK_REVIEW = 72 * 3600               # 72 hours
SLA_HITL_OVERRIDE_REVIEW = 24 * 3600          # 24 hours
SLA_HITL_OVERRIDE_EAB_REPORT = 72 * 3600      # 72 hours
SLA_NOTIFICATION = 30 * 86400                  # 30 days
SLA_CONTESTABILITY = 30 * 86400               # 30 days
SLA_SANCTIONS_UPDATE = 48 * 3600              # 48 hours
SLA_PUR_SYNC = 24 * 3600                      # 24 hours
SLA_DECOMMISSION_NOTICE = 30 * 86400          # 30 days
SLA_EAL_RESPONSE = 14 * 86400                 # 14 days
SLA_EXTENSION_REVIEW = 30 * 86400             # 30 days
SLA_APPEAL_FILING = 30 * 86400                # 30 days
SLA_APPEAL_DECISION = 60 * 86400              # 60 days
SLA_EAL_RETENTION_MIN = 365 * 86400           # 365 days
