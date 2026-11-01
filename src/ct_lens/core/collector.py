"""Collector — orchestrates a certificate source into a usable result.

Phase 1 keeps this deliberately small: normalise the user's target into a
crt.sh pattern, fetch records from a source, and summarise them. Caching,
pagination, and the full paginated fetch arrive in Phase 2.
"""

from __future__ import annotations

from collections import Counter

from ct_lens.core.models import CrtShRecord, ScanSummary
from ct_lens.core.sources.base import CertSource

#: How many example domains to include in a :class:`ScanSummary`.
SAMPLE_SIZE = 10

#: How many issuing CAs to list in a :class:`ScanSummary`.
TOP_ISSUERS = 10


def normalize_pattern(target: str) -> str:
    """Turn a user-supplied target into a crt.sh ``LIKE`` query pattern.

    crt.sh uses ``%`` as a SQL wildcard. We accept the common human spellings
    and always return a pattern that matches a domain *and* its sub-domains:

    ===================  ===================
    User types           crt.sh pattern
    ===================  ===================
    ``.lk`` / ``lk``     ``%.lk``
    ``example.com``      ``%.example.com``
    ``%.lk``             ``%.lk`` (unchanged)
    ===================  ===================

    Args:
        target: A TLD (``.lk``), a domain (``example.com``), or an explicit
            crt.sh pattern already containing ``%``.

    Returns:
        A crt.sh query pattern.

    Raises:
        ValueError: If ``target`` is empty.
    """
    target = target.strip().lower()
    if not target:
        raise ValueError("target must not be empty")

    # Caller already gave an explicit wildcard pattern — respect it.
    if "%" in target:
        return target

    # Normalise a leading dot so ".lk" and "lk" behave the same.
    target = target.lstrip(".")
    return f"%.{target}"


def summarize_records(pattern: str, records: list[CrtShRecord]) -> ScanSummary:
    """Build a :class:`ScanSummary` from fetched records.

    Counts total records, distinct domains, the most common issuing CAs, and
    picks a few example domains for a quick sanity check.
    """
    issuer_counts: Counter[str] = Counter()
    domains: dict[str, None] = {}  # insertion-ordered set

    for record in records:
        issuer_counts[record.issuer] += 1
        for domain in record.domains:
            domains.setdefault(domain, None)

    return ScanSummary(
        pattern=pattern,
        total_records=len(records),
        unique_domains=len(domains),
        top_issuers=issuer_counts.most_common(TOP_ISSUERS),
        sample_domains=list(domains)[:SAMPLE_SIZE],
    )


def scan(target: str, source: CertSource, *, limit: int | None = None) -> ScanSummary:
    """Run a Phase 1 scan: fetch records for ``target`` and summarise them.

    Args:
        target: TLD, domain, or crt.sh pattern (see :func:`normalize_pattern`).
        source: The certificate source to fetch from.
        limit: Optional cap on records fetched (handy for a quick spike).

    Returns:
        A :class:`ScanSummary`.
    """
    pattern = normalize_pattern(target)
    records = source.fetch(pattern, limit=limit)
    return summarize_records(pattern, records)
