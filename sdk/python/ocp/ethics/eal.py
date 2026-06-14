"""
Ethics Audit Log (EAL) — Append-only, SHA-3-256 chained, signed log.
Ref: OCP Ethics Bible v2.1 §36

Every EVL decision (pass and reject) is recorded. Entries are chained
via SHA-3-256 hashes for tamper evidence. Minimum 365-day retention.
"""
from __future__ import annotations
import hashlib
import json
import uuid
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from ocp.ethics.exceptions import EALIntegrityError


@dataclass
class EALEntry:
    """A single entry in the Ethics Audit Log."""
    eal_id: str = ""
    prev_hash: str = ""
    timestamp: str = ""
    message_id: str = ""
    message_type: str = ""
    sender: str = ""
    receiver: str = ""
    evl_checks_performed: list[str] = field(default_factory=list)
    evl_result: str = ""  # "PASS" or "REJECT"
    evl_code: str | None = None
    evl_reason: str | None = None
    remediation_hint: str | None = None
    warnings: list[str] = field(default_factory=list)
    node_id: str = ""
    # Extended fields (v2.1)
    cascade_event: dict | None = None
    sanctions_check: dict | None = None
    power_dynamics_flag: bool = False
    notification_required: bool = False
    generation_count_observed: int | None = None
    signature: str = ""

    def __post_init__(self):
        if not self.eal_id:
            self.eal_id = f"eal-{uuid.uuid4()}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    def compute_hash(self) -> str:
        """Compute SHA-3-256 hash of this entry for chaining."""
        d = self.to_dict()
        d.pop("signature", None)
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return hashlib.sha3_256(canonical.encode()).hexdigest()


class EAL:
    """
    Ethics Audit Log — append-only, chained, signed.

    Usage:
        eal = EAL(node_id="did:ocp:mainnet:node-001", signer=sign_fn)
        await eal.log(message_id=..., evl_result=result)
        entries = await eal.query(sender="did:ocp:...", limit=100)
    """

    def __init__(self, node_id: str, signer=None, storage=None):
        self.node_id = node_id
        self.signer = signer  # async fn(bytes) -> str
        self.storage = storage  # persistence backend
        self._chain: list[EALEntry] = []
        self._last_hash = "0" * 64  # genesis

    async def log(self, message_id: str, message_type: str,
                  sender: str, receiver: str, evl_result,
                  **extra_fields) -> EALEntry:
        """Append a new entry to the log."""
        entry = EALEntry(
            prev_hash=self._last_hash,
            message_id=message_id,
            message_type=message_type,
            sender=sender,
            receiver=receiver,
            evl_checks_performed=evl_result.checks_performed if hasattr(evl_result, "checks_performed") else [],
            evl_result=evl_result.status if hasattr(evl_result, "status") else str(evl_result),
            evl_code=evl_result.code.value if hasattr(evl_result, "code") and evl_result.code else None,
            evl_reason=evl_result.reason if hasattr(evl_result, "reason") else None,
            remediation_hint=evl_result.remediation if hasattr(evl_result, "remediation") else None,
            warnings=evl_result.warnings if hasattr(evl_result, "warnings") else [],
            node_id=self.node_id,
            **extra_fields
        )

        # Sign the entry
        if self.signer:
            canonical = json.dumps(entry.to_dict(), sort_keys=True, separators=(",", ":"))
            entry.signature = await self.signer(canonical.encode())

        # Update chain
        self._last_hash = entry.compute_hash()
        self._chain.append(entry)

        # Persist
        if self.storage:
            await self.storage.append(entry)

        return entry

    async def verify_chain(self) -> bool:
        """Verify the integrity of the entire EAL chain."""
        prev_hash = "0" * 64
        for entry in self._chain:
            if entry.prev_hash != prev_hash:
                raise EALIntegrityError(
                    f"Chain break at {entry.eal_id}: expected prev_hash "
                    f"{prev_hash[:16]}..., got {entry.prev_hash[:16]}..."
                )
            prev_hash = entry.compute_hash()
        return True

    async def query(self, sender: str = None, receiver: str = None,
                    evl_result: str = None, limit: int = 100,
                    since: str = None) -> list[EALEntry]:
        """Query the EAL with filters."""
        results = []
        for entry in reversed(self._chain):
            if sender and entry.sender != sender:
                continue
            if receiver and entry.receiver != receiver:
                continue
            if evl_result and entry.evl_result != evl_result:
                continue
            if since and entry.timestamp < since:
                break
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    @property
    def length(self) -> int:
        return len(self._chain)

    @property
    def last_entry(self) -> EALEntry | None:
        return self._chain[-1] if self._chain else None
