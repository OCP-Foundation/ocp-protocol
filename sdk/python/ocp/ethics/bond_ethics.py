"""
Bond Record Ethics Extensions.
Ref: Integration Spec INT-034,035,052

IP ownership, indemnification, dual-use acknowledgment, power dynamics.
"""
from __future__ import annotations


class BondEthicsExtension:
    """
    Extends Bond Records with ethics fields.

    Usage:
        ext = BondEthicsExtension()
        bond = ext.extend(bond_record,
            ip_ownership="joint", indemnification="executing_party")
    """

    def extend(self, bond_record: dict,
               ip_ownership: str = "joint",
               indemnification: str = "executing_party",
               dual_use_acknowledgment: bool = False,
               power_dynamics_review: bool = False) -> dict:
        """Add ethics fields to a Bond Record."""
        bond_record = dict(bond_record)
        ethics = bond_record.setdefault("permissions", {}).setdefault("ethics", {})

        ethics["ip_ownership"] = ip_ownership
        ethics["indemnification"] = indemnification
        ethics["dual_use_acknowledgment"] = dual_use_acknowledgment
        ethics["power_dynamics_review"] = power_dynamics_review

        return bond_record

    def validate(self, bond_record: dict) -> tuple[bool, list[str]]:
        """Validate bond ethics fields."""
        issues = []
        ethics = bond_record.get("permissions", {}).get("ethics", {})

        # Check IP ownership
        ip = ethics.get("ip_ownership")
        if ip and ip not in ("joint", "requester", "responder", "custom"):
            issues.append(f"Invalid ip_ownership: {ip}")

        # Check indemnification
        ind = ethics.get("indemnification")
        if ind and ind not in ("executing_party", "requesting_party", "shared", "custom"):
            issues.append(f"Invalid indemnification: {ind}")

        # Check for dissolution penalties (prohibited)
        if bond_record.get("dissolution_penalty"):
            issues.append("Dissolution penalties are prohibited")

        # Check for lock-in periods
        if bond_record.get("lock_in_period"):
            issues.append("Lock-in periods exceeding natural expiry are prohibited")

        return len(issues) == 0, issues
