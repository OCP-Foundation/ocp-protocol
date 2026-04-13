"""OCP exception hierarchy.

All OCP-specific exceptions inherit from :class:`OCPError`. Transport,
authentication, validation, trust, and privacy subsystems each have a
dedicated exception class so callers can handle failures granularly.
"""

from __future__ import annotations


class OCPError(Exception):
    """Base exception for all OCP errors.

    Attributes:
        code: Optional OCP error code (e.g., ``"OCP-400"``).
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code

    def __repr__(self) -> str:
        cls = type(self).__name__
        if self.code:
            return f"{cls}(code={self.code!r}, message={str(self)!r})"
        return f"{cls}(message={str(self)!r})"


class OCPAuthError(OCPError):
    """Authentication or authorization failure.

    Raised when an agent fails the WebSocket auth handshake, presents
    an invalid signature, or attempts an operation requiring a higher
    trust level than it holds.

    Typical codes: ``OCP-401``, ``OCP-403``.
    """


class OCPTransportError(OCPError):
    """Transport-layer failure.

    Raised on connection failures, DNS resolution errors, TLS
    handshake failures, message delivery failures, and routing errors.

    Typical codes: ``OCP-502``, ``OCP-503``.
    """


class OCPValidationError(OCPError):
    """Message or schema validation failure.

    Raised when an outgoing or incoming OCPUMF message fails structural
    validation, schema compliance, or business-rule checks.

    Typical code: ``OCP-400``.
    """


class OCPTrustError(OCPError):
    """Insufficient trust level or bond permissions.

    Raised when an agent attempts an operation that its current trust
    level or bond permissions do not allow.

    Typical code: ``OCP-403``.
    """


class OCPPrivacyViolation(OCPError):
    """Privacy Validation Layer rejection.

    Raised when a knowledge payload fails one of the PVL checks
    (PII detection, anonymization, differential privacy, provenance,
    or size limits).

    Attributes:
        pvl_code: The specific PVL rejection code (``PVL-001`` through ``PVL-006``).
    """

    def __init__(self, message: str, pvl_code: str) -> None:
        super().__init__(message, code=pvl_code)
        self.pvl_code = pvl_code

    def __repr__(self) -> str:
        return f"OCPPrivacyViolation(pvl_code={self.pvl_code!r}, message={str(self)!r})"


class OCPTimeoutError(OCPError):
    """Operation timed out.

    Raised when an acknowledgement, task response, or auth handshake
    is not received within the protocol-specified time window.

    Typical code: ``OCP-408``.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="OCP-408")


class OCPRateLimitError(OCPError):
    """Rate limit exceeded.

    Raised when the agent has exceeded the allowable request rate for
    a given operation category.

    Attributes:
        retry_after: Number of seconds the caller should wait before retrying.
    """

    def __init__(self, message: str, retry_after: int) -> None:
        super().__init__(message, code="OCP-429")
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"OCPRateLimitError(retry_after={self.retry_after}, message={str(self)!r})"


class OCPAgentNotFoundError(OCPError):
    """Agent not found in registry.

    Raised when a DID lookup, registry resolve, or message routing
    attempt fails because the target agent does not exist or is inactive.

    Typical code: ``OCP-404``.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="OCP-404")


class OCPConsensusError(OCPError):
    """Consensus protocol error.

    Raised on invalid votes, quorum failures, or deadline violations
    during a consensus round.
    """


class OCPRecoveryError(OCPError):
    """Key recovery error.

    Raised when share generation, distribution, or reconstruction
    fails — for example, due to corrupted shares or a fingerprint
    mismatch.
    """
    