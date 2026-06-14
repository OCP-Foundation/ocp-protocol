"""
Consent Token subsystem — issue, validate, revoke, propagate.
Ref: OCP Ethics Bible v2.1 §11
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from ocp.ethics.constants import ConsentBasis, REGULATED_DOMAINS


@dataclass
class ConsentToken:
    """A cryptographically signed consent artifact."""
    token_id: str = ""
    scope: str = ""
    basis: str = ""
    reference: str = ""
    issued_at: str = ""
    expires_at: str = ""
    issuer: str = ""
    subject_count: int | None = None
    anonymization_method: str | None = None
    k_value: int | None = None
    geographic_scope: str | None = None
    revocable: bool = True
    revocation_endpoint: str | None = None
    signature: str = ""

    def __post_init__(self):
        if not self.token_id:
            self.token_id = f"ct-{uuid.uuid4()}"
        if not self.issued_at:
            self.issued_at = datetime.now(timezone.utc).isoformat()

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        now = datetime.now(timezone.utc).isoformat()
        return now > self.expires_at

    def covers_domain(self, domain: str) -> bool:
        """Check if this token's scope covers the given domain."""
        return domain.startswith(self.scope) or self.scope.startswith(domain)

    def to_dict(self) -> dict:
        d = {
            "token_id": self.token_id, "scope": self.scope,
            "basis": self.basis, "reference": self.reference,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
            "issuer": self.issuer, "revocable": self.revocable,
            "signature": self.signature,
        }
        if self.subject_count is not None:
            d["subject_count"] = self.subject_count
        if self.anonymization_method:
            d["anonymization_method"] = self.anonymization_method
        if self.geographic_scope:
            d["geographic_scope"] = self.geographic_scope
        if self.revocation_endpoint:
            d["revocation_endpoint"] = self.revocation_endpoint
        return d


class ConsentManager:
    """
    Manages consent token lifecycle.

    Usage:
        mgr = ConsentManager(verifier=verify_fn, revocation_checker=check_fn)
        token = mgr.issue(scope="healthcare.oncology", basis="irb_approval", ...)
        valid = await mgr.validate_for_domain(tokens, "healthcare.oncology")
    """

    def __init__(self, verifier=None, revocation_checker=None):
        self.verifier = verifier
        self.revocation_checker = revocation_checker
        self._issued: dict[str, ConsentToken] = {}
        self._revoked: set[str] = set()

    def issue(self, scope: str, basis: str, reference: str,
              expires_at: str, issuer: str, signer=None, **kwargs) -> ConsentToken:
        token = ConsentToken(
            scope=scope, basis=basis, reference=reference,
            expires_at=expires_at, issuer=issuer, **kwargs
        )
        if signer:
            token.signature = signer(token.to_dict())
        self._issued[token.token_id] = token
        return token

    async def validate_for_domain(self, tokens: list[dict], domain: str) -> bool:
        """Check if at least one valid token covers the domain."""
        for t in tokens:
            token = ConsentToken(**{k: v for k, v in t.items()
                                    if k in ConsentToken.__dataclass_fields__})
            if token.token_id in self._revoked:
                continue
            if token.is_expired():
                continue
            if not token.covers_domain(domain):
                continue
            if self.verifier and not await self.verifier(token):
                continue
            if self.revocation_checker and await self.revocation_checker(token):
                self._revoked.add(token.token_id)
                continue
            return True
        return False

    def revoke(self, token_id: str):
        self._revoked.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self._revoked
