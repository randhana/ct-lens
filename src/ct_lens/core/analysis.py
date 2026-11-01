"""Ecosystem analysis — the ".lk report card" (README §3.3).

Turns a list of normalised :class:`~ct_lens.core.models.Certificate` into
aggregate statistics:

* **CA market share** — who issues HTTPS certificates for the TLD, and how
  concentrated the market is.
* **Certificate lifetimes** — distribution and trend, as the industry moves to
  ever-shorter certificates (90-day, and the upcoming 47-day maximum).
* **Issuance over time** — volume/growth by month.
* **Key types & signature algorithms** — only populated when the dataset was
  enriched (see :mod:`ct_lens.core.enrich`).

Everything here is pure standard-library Python: no pandas, no plotting. That
keeps the core light and the results trivially testable. Charts are a separate,
optional layer (:mod:`ct_lens.core.charts`).
"""

from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass, field

from ct_lens.core.models import Certificate

#: Lifetime buckets (in days) used for the distribution, chosen around the
#: industry's meaningful thresholds: the 47-day future maximum, the 90-day
#: Let's Encrypt norm, ~1-year legacy certs, and anything longer.
LIFETIME_BUCKETS: list[tuple[str, int, int]] = [
    ("<=47 days", 0, 47),
    ("48-90 days", 48, 90),
    ("91-180 days", 91, 180),
    ("181-397 days", 181, 397),
    (">397 days", 398, 10**9),
]


@dataclass(slots=True)
class CAShare:
    """One Certificate Authority's share of issuance."""

    issuer: str
    count: int
    share: float  # fraction in [0, 1]


@dataclass(slots=True)
class LifetimeStats:
    """Summary statistics for certificate lifetimes (in days)."""

    count: int
    min_days: int | None
    max_days: int | None
    mean_days: float | None
    median_days: float | None
    buckets: list[tuple[str, int]] = field(default_factory=list)


@dataclass(slots=True)
class PeriodCount:
    """Issuance volume for one period (e.g. ``"2024-03"``)."""

    period: str
    count: int


@dataclass(slots=True)
class EcosystemAnalysis:
    """The full ecosystem report for one scan."""

    pattern: str
    total_certificates: int
    unique_domains: int
    wildcard_count: int
    ca_shares: list[CAShare]
    lifetimes: LifetimeStats
    issuance_by_month: list[PeriodCount]
    key_types: list[tuple[str, int]]
    signature_algorithms: list[tuple[str, int]]

    @property
    def ca_concentration_top1(self) -> float:
        """Share held by the single largest CA (0 if there are none)."""
        return self.ca_shares[0].share if self.ca_shares else 0.0

    @property
    def ca_concentration_top3(self) -> float:
        """Combined share of the three largest CAs."""
        return sum(item.share for item in self.ca_shares[:3])


def ca_shares(certificates: list[Certificate]) -> list[CAShare]:
    """Return per-CA issuance share, most issued first."""
    counts = Counter(cert.issuer for cert in certificates)
    total = sum(counts.values())
    return [
        CAShare(issuer=issuer, count=count, share=(count / total if total else 0.0))
        for issuer, count in counts.most_common()
    ]


def lifetime_stats(certificates: list[Certificate]) -> LifetimeStats:
    """Summarise certificate lifetimes and bucket them by duration."""
    lifetimes = [c.lifetime_days for c in certificates if c.lifetime_days is not None]

    bucket_counts = {label: 0 for label, _, _ in LIFETIME_BUCKETS}
    for days in lifetimes:
        for label, low, high in LIFETIME_BUCKETS:
            if low <= days <= high:
                bucket_counts[label] += 1
                break

    if not lifetimes:
        return LifetimeStats(0, None, None, None, None, list(bucket_counts.items()))

    return LifetimeStats(
        count=len(lifetimes),
        min_days=min(lifetimes),
        max_days=max(lifetimes),
        mean_days=round(statistics.fmean(lifetimes), 1),
        median_days=statistics.median(lifetimes),
        buckets=list(bucket_counts.items()),
    )


def issuance_by_month(certificates: list[Certificate]) -> list[PeriodCount]:
    """Count certificates issued per calendar month (by ``not_before``)."""
    counts: Counter[str] = Counter()
    for cert in certificates:
        if cert.not_before is not None:
            counts[cert.not_before.strftime("%Y-%m")] += 1
    return [PeriodCount(period, counts[period]) for period in sorted(counts)]


def _distribution(values: list[str | None]) -> list[tuple[str, int]]:
    """Count non-null string values, most common first."""
    counts = Counter(value for value in values if value)
    return counts.most_common()


def analyze(pattern: str, certificates: list[Certificate]) -> EcosystemAnalysis:
    """Build the full :class:`EcosystemAnalysis` for a dataset."""
    unique_domains = {domain for cert in certificates for domain in cert.domains}
    return EcosystemAnalysis(
        pattern=pattern,
        total_certificates=len(certificates),
        unique_domains=len(unique_domains),
        wildcard_count=sum(1 for cert in certificates if cert.is_wildcard),
        ca_shares=ca_shares(certificates),
        lifetimes=lifetime_stats(certificates),
        issuance_by_month=issuance_by_month(certificates),
        key_types=_distribution([cert.key_type for cert in certificates]),
        signature_algorithms=_distribution([cert.signature_algorithm for cert in certificates]),
    )
