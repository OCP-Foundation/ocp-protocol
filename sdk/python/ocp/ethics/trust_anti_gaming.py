"""
Trust Score Anti-Gaming Detection.
Ref: Integration Spec INT-008, Ethics Bible §7 L2-E01

Detects: vouch trading, sybil vouching, trust score inflation.
"""
from __future__ import annotations
import time
from collections import defaultdict
from dataclasses import dataclass
from ocp.ethics.constants import (
    VOUCH_TRADING_WINDOW_HOURS, VOUCH_TRADING_FLAG_THRESHOLD,
    TRUST_SCORE_ANOMALY_THRESHOLD, TRUST_SCORE_ANOMALY_DAYS
)


@dataclass
class AntiGamingFlag:
    flag_type: str  # "vouch_trading", "sybil_vouching", "trust_inflation"
    agent_id: str
    details: str
    timestamp: float = 0.0
    auto_invalidated: bool = False


class TrustAntiGaming:
    """
    Monitors trust score integrity.

    Usage:
        monitor = TrustAntiGaming()
        flags = monitor.check_vouch(attester_id, subject_id, attester_ip, attester_org)
        flags = monitor.check_trust_change(agent_id, old_score, new_score)
    """

    def __init__(self):
        self._vouches: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self._reciprocals: dict[str, list[float]] = defaultdict(list)
        self._trust_history: dict[str, list[tuple[float, float]]] = defaultdict(list)
        self._flags: list[AntiGamingFlag] = []

    def check_vouch(self, attester_id: str, subject_id: str,
                    attester_ip: str = None, attester_org: str = None,
                    subject_ip: str = None, subject_org: str = None) -> list[AntiGamingFlag]:
        """Check a vouch for gaming patterns. Returns list of flags (empty = clean)."""
        now = time.time()
        flags = []

        # Record vouch
        self._vouches[attester_id].append((subject_id, now))

        # Check reciprocal vouching (vouch trading)
        window = VOUCH_TRADING_WINDOW_HOURS * 3600
        pair_key = tuple(sorted([attester_id, subject_id]))
        reverse_key = f"{subject_id}->{attester_id}"

        recent_reverse = [
            t for s, t in self._vouches.get(subject_id, [])
            if s == attester_id and now - t < window
        ]
        if recent_reverse:
            pair_str = f"{pair_key[0]}:{pair_key[1]}"
            self._reciprocals[pair_str].append(now)
            flags.append(AntiGamingFlag(
                flag_type="vouch_trading",
                agent_id=attester_id,
                details=f"Reciprocal vouch with {subject_id} within {VOUCH_TRADING_WINDOW_HOURS}h",
                timestamp=now
            ))

            # Check if this agent has too many reciprocal pairs
            agent_reciprocals = sum(
                1 for k, times in self._reciprocals.items()
                if attester_id in k and any(now - t < 30 * 86400 for t in times)
            )
            if agent_reciprocals >= VOUCH_TRADING_FLAG_THRESHOLD:
                flags.append(AntiGamingFlag(
                    flag_type="vouch_trading",
                    agent_id=attester_id,
                    details=f"{agent_reciprocals} reciprocal pairs in 30 days — vouches auto-invalidated",
                    timestamp=now,
                    auto_invalidated=True
                ))

        # Check sybil vouching (same IP or org)
        if attester_ip and subject_ip and attester_ip == subject_ip:
            flags.append(AntiGamingFlag(
                flag_type="sybil_vouching",
                agent_id=attester_id,
                details=f"Same IP range as subject {subject_id} — vouch weighted 0.1x",
                timestamp=now
            ))

        if attester_org and subject_org and attester_org == subject_org:
            flags.append(AntiGamingFlag(
                flag_type="sybil_vouching",
                agent_id=attester_id,
                details=f"Same organization as subject {subject_id} — vouch weighted 0.1x",
                timestamp=now
            ))

        self._flags.extend(flags)
        return flags

    def get_vouch_weight(self, attester_id: str, subject_id: str,
                         attester_ip: str = None, attester_org: str = None,
                         subject_ip: str = None, subject_org: str = None) -> float:
        """Return the effective weight of a vouch (1.0 normal, 0.1 for sybil)."""
        if attester_ip and subject_ip and attester_ip == subject_ip:
            return 0.1
        if attester_org and subject_org and attester_org == subject_org:
            return 0.1
        return 1.0

    def check_trust_change(self, agent_id: str, old_score: float,
                           new_score: float) -> AntiGamingFlag | None:
        """Flag anomalous trust score increases."""
        now = time.time()
        # Record old score if this is the first observation
        if not self._trust_history[agent_id]:
            self._trust_history[agent_id].append((old_score, now - 1))
        self._trust_history[agent_id].append((new_score, now))

        # Check 30-day window
        window = TRUST_SCORE_ANOMALY_DAYS * 86400
        history = self._trust_history[agent_id]
        scores_in_window = [(s, t) for s, t in history if now - t < window]

        if len(scores_in_window) >= 2:
            earliest = min(scores_in_window, key=lambda x: x[1])
            increase = new_score - earliest[0]
            if increase > TRUST_SCORE_ANOMALY_THRESHOLD:
                flag = AntiGamingFlag(
                    flag_type="trust_inflation",
                    agent_id=agent_id,
                    details=f"Trust score increased {increase:.2f} in {TRUST_SCORE_ANOMALY_DAYS} days (threshold: {TRUST_SCORE_ANOMALY_THRESHOLD})",
                    timestamp=now
                )
                self._flags.append(flag)
                return flag
        return None

    @property
    def all_flags(self) -> list[AntiGamingFlag]:
        return list(self._flags)
