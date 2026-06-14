"""
Compute Footprint Tracking and Aggregation.
Ref: Integration Spec INT-014,025, Ethics Bible §15

Tracks energy, FLOPs, and carbon for knowledge generation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ComputeFootprint:
    flops_estimated: float = 0.0
    energy_kwh: float = 0.0
    carbon_gco2e: float = 0.0
    datacenter_region: str = ""

    def to_dict(self) -> dict:
        d = {}
        if self.flops_estimated: d["flops_estimated"] = self.flops_estimated
        if self.energy_kwh: d["energy_kwh"] = self.energy_kwh
        if self.carbon_gco2e: d["carbon_gco2e"] = self.carbon_gco2e
        if self.datacenter_region: d["datacenter_region"] = self.datacenter_region
        return d


class ComputeFootprintTracker:
    """Tracks and aggregates compute footprints across knowledge generation."""

    def __init__(self):
        self._entries: list[tuple[str, ComputeFootprint, str]] = []

    def record(self, message_id: str, footprint: ComputeFootprint):
        ts = datetime.now(timezone.utc).isoformat()
        self._entries.append((message_id, footprint, ts))

    def aggregate(self, since: str = None) -> dict:
        """Aggregate footprints for reporting."""
        entries = self._entries
        if since:
            entries = [(m, f, t) for m, f, t in entries if t >= since]

        total_flops = sum(f.flops_estimated for _, f, _ in entries)
        total_kwh = sum(f.energy_kwh for _, f, _ in entries)
        total_carbon = sum(f.carbon_gco2e for _, f, _ in entries)

        return {
            "total_messages": len(entries),
            "total_flops": total_flops,
            "total_energy_kwh": total_kwh,
            "total_carbon_gco2e": total_carbon,
            "period_start": entries[0][2] if entries else None,
            "period_end": entries[-1][2] if entries else None,
        }
