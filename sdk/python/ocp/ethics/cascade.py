"""
Cascade Circuit Breaker — pauses propagation at 50+ agents/24h.
Ref: OCP Ethics Bible v2.1 §27
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from collections import defaultdict
from ocp.ethics.constants import (
    CASCADE_THRESHOLD_AGENTS, CASCADE_THRESHOLD_HOURS, CASCADE_PAUSE_MINUTES
)


@dataclass
class CascadeEvent:
    """Record of a cascade trigger."""
    message_id: str
    agent_count: int
    triggered_at: float
    pause_until: float
    cleared: bool = False
    cleared_by: str | None = None


class CascadeCircuitBreaker:
    """
    Monitors message propagation velocity. Triggers pause at threshold.

    Usage:
        breaker = CascadeCircuitBreaker()
        breaker.record_propagation("msg-123", "did:ocp:mainnet:agent-abc")
        is_blocked = await breaker.check("msg-123")
    """

    def __init__(self, threshold_agents: int = CASCADE_THRESHOLD_AGENTS,
                 window_hours: int = CASCADE_THRESHOLD_HOURS,
                 pause_minutes: int = CASCADE_PAUSE_MINUTES):
        self.threshold = threshold_agents
        self.window = window_hours * 3600
        self.pause_duration = pause_minutes * 60
        self._propagations: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self._active_pauses: dict[str, CascadeEvent] = {}

    def record_propagation(self, message_id: str, agent_id: str):
        """Record that an agent has propagated a message."""
        now = time.time()
        self._propagations[message_id].append((agent_id, now))
        # Clean old entries
        cutoff = now - self.window
        self._propagations[message_id] = [
            (a, t) for a, t in self._propagations[message_id] if t > cutoff
        ]

    async def check(self, message_id: str) -> bool:
        """Check if message is paused. Returns True if blocked."""
        now = time.time()
        # Check active pause
        if message_id in self._active_pauses:
            event = self._active_pauses[message_id]
            if event.cleared:
                del self._active_pauses[message_id]
                return False
            if now < event.pause_until:
                return True
            del self._active_pauses[message_id]
            return False

        # Check if threshold exceeded
        entries = self._propagations.get(message_id, [])
        unique_agents = set(a for a, _ in entries)
        if len(unique_agents) >= self.threshold:
            event = CascadeEvent(
                message_id=message_id,
                agent_count=len(unique_agents),
                triggered_at=now,
                pause_until=now + self.pause_duration
            )
            self._active_pauses[message_id] = event
            return True

        return False

    def clear_pause(self, message_id: str, cleared_by: str):
        """Manually clear a cascade pause (originator confirmation)."""
        if message_id in self._active_pauses:
            self._active_pauses[message_id].cleared = True
            self._active_pauses[message_id].cleared_by = cleared_by

    def get_active_cascades(self) -> list[CascadeEvent]:
        now = time.time()
        return [e for e in self._active_pauses.values()
                if not e.cleared and now < e.pause_until]
