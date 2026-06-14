"""
AI Risk Classification Engine — 4-tier system.
Ref: OCP Ethics Bible v2.1 §4, Appendix B
"""
from __future__ import annotations
from ocp.ethics.constants import RiskTier, UNACCEPTABLE_CAPABILITIES


# Domain-capability → risk tier mapping
RISK_MATRIX: dict[tuple[str, str], RiskTier] = {
    ("healthcare", "cap:vision:imaging"): RiskTier.HIGH,
    ("healthcare", "cap:nlp:report_gen"): RiskTier.HIGH,
    ("healthcare", "*"): RiskTier.HIGH,
    ("finance.credit", "cap:finance:risk_analysis"): RiskTier.HIGH,
    ("finance.trading", "cap:finance:portfolio_optimization"): RiskTier.HIGH,
    ("legal.litigation", "cap:nlp:classification"): RiskTier.HIGH,
    ("legal.compliance", "cap:nlp:classification"): RiskTier.LIMITED,
    ("education.assessment", "cap:nlp:classification"): RiskTier.HIGH,
    ("education.tutoring", "cap:nlp:summarization"): RiskTier.LIMITED,
    ("research.data_analysis", "cap:data:clustering"): RiskTier.LIMITED,
    ("engineering.software", "cap:code:generation"): RiskTier.LIMITED,
}


class RiskClassifier:
    """
    Classifies agents into risk tiers based on domains and capabilities.

    Usage:
        classifier = RiskClassifier()
        tier = classifier.classify(domains=["healthcare.oncology"],
                                    capabilities=["cap:vision:imaging"])
    """

    def __init__(self, custom_matrix: dict | None = None):
        self._matrix = {**RISK_MATRIX}
        if custom_matrix:
            self._matrix.update(custom_matrix)

    def classify(self, domains: list[str], capabilities: list[str]) -> RiskTier:
        """Classify based on domains and capabilities. Returns highest applicable tier."""
        # Check for unacceptable capabilities (wildcard matching)
        import fnmatch
        for cap in capabilities:
            for blocked in UNACCEPTABLE_CAPABILITIES:
                if fnmatch.fnmatch(cap, blocked):
                    return RiskTier.UNACCEPTABLE

        highest = RiskTier.MINIMAL

        for domain in domains:
            for cap in capabilities:
                # Exact match
                key = (domain, cap)
                if key in self._matrix:
                    tier = self._matrix[key]
                    if self._tier_rank(tier) > self._tier_rank(highest):
                        highest = tier
                    continue

                # Domain wildcard
                key = (domain, "*")
                if key in self._matrix:
                    tier = self._matrix[key]
                    if self._tier_rank(tier) > self._tier_rank(highest):
                        highest = tier
                    continue

                # Parent domain match
                parts = domain.split(".")
                for i in range(len(parts)):
                    parent = ".".join(parts[:i+1])
                    key = (parent, cap)
                    if key in self._matrix:
                        tier = self._matrix[key]
                        if self._tier_rank(tier) > self._tier_rank(highest):
                            highest = tier

        return highest

    @staticmethod
    def _tier_rank(tier: RiskTier) -> int:
        return {"minimal": 0, "limited": 1, "high": 2, "unacceptable": 3}[tier.value]
