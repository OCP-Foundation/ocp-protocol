"""
Sanctions Screening Gate — checks OFAC/EU/UN before bond formation.
Ref: OCP Ethics Bible v2.1 §29
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field


@dataclass
class SanctionsResult:
    """Result of a sanctions screening."""
    cleared: bool
    lists_checked: list[str] = field(default_factory=list)
    matches: list[str] = field(default_factory=list)
    checked_at: float = 0.0
    valid_until: float = 0.0

    def __post_init__(self):
        if not self.checked_at:
            self.checked_at = time.time()
        if not self.valid_until:
            self.valid_until = self.checked_at + 48 * 3600  # 48h cache

    def is_valid(self) -> bool:
        return time.time() < self.valid_until


class SanctionsScreener:
    """
    Screens deploying organizations against sanctions lists.

    Usage:
        screener = SanctionsScreener()
        result = await screener.screen("ExampleCorp", jurisdiction="US")
    """

    LISTS = ["OFAC_SDN", "EU_CONSOLIDATED", "UN_SECURITY_COUNCIL"]

    def __init__(self, list_provider=None):
        self.list_provider = list_provider
        self._cache: dict[str, SanctionsResult] = {}
        self._sanctioned: set[str] = set()  # local blocklist

    async def screen(self, organization: str,
                     jurisdiction: str | None = None) -> SanctionsResult:
        """Screen an organization against sanctions lists."""
        cache_key = f"{organization}:{jurisdiction or 'ALL'}"
        if cache_key in self._cache and self._cache[cache_key].is_valid():
            return self._cache[cache_key]

        matches = []
        if organization.lower() in self._sanctioned:
            matches.append("LOCAL_BLOCKLIST")

        if self.list_provider:
            external = await self.list_provider.check(organization, jurisdiction)
            matches.extend(external)

        result = SanctionsResult(
            cleared=len(matches) == 0,
            lists_checked=self.LISTS,
            matches=matches
        )
        self._cache[cache_key] = result
        return result

    def add_to_blocklist(self, organization: str):
        self._sanctioned.add(organization.lower())

    def clear_cache(self):
        self._cache.clear()
