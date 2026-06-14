"""
Ethics exception hierarchy.
"""
from ocp.ethics.constants import EVLCode, Severity


class EthicsError(Exception):
    """Base exception for all ethics violations."""
    def __init__(self, message: str, code: EVLCode | None = None,
                 severity: Severity = Severity.MEDIUM):
        super().__init__(message)
        self.code = code
        self.severity = severity


class EVLRejection(EthicsError):
    """Raised when EVL rejects a message."""
    def __init__(self, code: EVLCode, reason: str, message_id: str | None = None,
                 remediation: str | None = None):
        super().__init__(reason, code=code)
        self.reason = reason
        self.message_id = message_id
        self.remediation = remediation


class ProhibitedUseViolation(EVLRejection):
    """Raised for prohibited use violations (PU-001 through PU-010)."""
    def __init__(self, code: EVLCode, reason: str, **kwargs):
        super().__init__(code, reason, **kwargs)
        self.severity = Severity.CRITICAL


class ConsentError(EVLRejection):
    """Raised for consent token violations."""
    def __init__(self, reason: str, **kwargs):
        super().__init__(EVLCode.EVL_007, reason, **kwargs)


class HITLRequired(EVLRejection):
    """Raised when human-in-the-loop approval is missing."""
    def __init__(self, reason: str, **kwargs):
        super().__init__(EVLCode.EVL_008, reason, **kwargs)


class CascadeTriggered(EVLRejection):
    """Raised when cascade circuit breaker activates."""
    def __init__(self, message_id: str, agent_count: int, **kwargs):
        reason = f"Cascade: {agent_count} agents propagated message {message_id}"
        super().__init__(EVLCode.EVL_012, reason, message_id=message_id, **kwargs)
        self.agent_count = agent_count


class SanctionsViolation(EthicsError):
    """Raised when sanctions screening fails."""
    pass


class ModelCollapseRisk(EthicsError):
    """Raised when model collapse indicators are detected."""
    pass


class EALIntegrityError(EthicsError):
    """Raised when EAL chain integrity is broken."""
    def __init__(self, message: str):
        super().__init__(message, severity=Severity.CRITICAL)
