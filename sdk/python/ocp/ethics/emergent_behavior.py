"""
Emergent Multi-Agent Behavior Detection.
Ref: Integration Spec INT-049, Ethics Bible §27

Monitors network-level patterns for harmful emergent behavior.
"""
from __future__ import annotations
import time
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class EmergentBehaviorAlert:
    alert_type: str  # "cascade_amplification", "herding", "collective_action", "synchronized_output"
    agents_involved: list[str]
    domain: str
    details: str
    timestamp: float = 0.0
    sigma_deviation: float = 0.0


class EmergentBehaviorDetector:
    """
    Monitors for harmful emergent behavior across the agent network.

    Usage:
        detector = EmergentBehaviorDetector()
        detector.record_output(agent_id, domain, output_hash)
        alerts = detector.check_collective_action()
    """

    COLLECTIVE_ACTION_THRESHOLD = 10  # agents
    COLLECTIVE_ACTION_WINDOW = 3600   # 1 hour
    ANOMALY_SIGMA_THRESHOLD = 3.0

    def __init__(self):
        self._outputs: dict[str, list[tuple[str, str, float]]] = defaultdict(list)
        self._propagation_rates: list[float] = []
        self._alerts: list[EmergentBehaviorAlert] = []

    def record_output(self, agent_id: str, domain: str, output_hash: str):
        """Record an agent's output for collective action tracking."""
        now = time.time()
        self._outputs[domain].append((agent_id, output_hash, now))
        # Prune old entries
        cutoff = now - self.COLLECTIVE_ACTION_WINDOW
        self._outputs[domain] = [
            (a, h, t) for a, h, t in self._outputs[domain] if t > cutoff
        ]

    def check_collective_action(self) -> list[EmergentBehaviorAlert]:
        """Check for collective action: many agents producing similar outputs."""
        now = time.time()
        alerts = []

        for domain, entries in self._outputs.items():
            # Group by output hash
            hash_groups: dict[str, list[str]] = defaultdict(list)
            for agent_id, output_hash, _ in entries:
                hash_groups[output_hash].append(agent_id)

            for output_hash, agents in hash_groups.items():
                unique_agents = list(set(agents))
                if len(unique_agents) >= self.COLLECTIVE_ACTION_THRESHOLD:
                    alert = EmergentBehaviorAlert(
                        alert_type="collective_action",
                        agents_involved=unique_agents,
                        domain=domain,
                        details=(
                            f"{len(unique_agents)} agents produced similar outputs "
                            f"in domain {domain} within {self.COLLECTIVE_ACTION_WINDOW}s"
                        ),
                        timestamp=now
                    )
                    alerts.append(alert)
                    self._alerts.append(alert)

        return alerts

    def record_propagation_rate(self, rate: float):
        """Record a propagation rate for baseline tracking."""
        self._propagation_rates.append(rate)
        if len(self._propagation_rates) > 10000:
            self._propagation_rates = self._propagation_rates[-5000:]

    def check_anomalous_propagation(self, current_rate: float) -> EmergentBehaviorAlert | None:
        """Check if current propagation rate is anomalous (>3 sigma)."""
        if len(self._propagation_rates) < 100:
            return None

        import statistics
        mean = statistics.mean(self._propagation_rates)
        stdev = statistics.stdev(self._propagation_rates)
        if stdev == 0:
            return None

        sigma = (current_rate - mean) / stdev
        if sigma > self.ANOMALY_SIGMA_THRESHOLD:
            alert = EmergentBehaviorAlert(
                alert_type="cascade_amplification",
                agents_involved=[],
                domain="network",
                details=f"Propagation rate {current_rate:.1f} is {sigma:.1f}σ above baseline",
                timestamp=time.time(),
                sigma_deviation=sigma
            )
            self._alerts.append(alert)
            return alert
        return None

    @property
    def all_alerts(self) -> list[EmergentBehaviorAlert]:
        return list(self._alerts)
