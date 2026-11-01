"""Collector — orchestrates a source (+ cache) into usable records.

The collector is the one place that ties together "where do records come from"
(:mod:`ct_lens.core.sources`) and "have we already fetched them"
(:mod:`ct_lens.core.cache`). Everything downstream (analysis, findings,
reporting) consumes the collector's output and never talks to crt.sh directly.

Caching behaviour
-----------------
A full fetch always stores the **complete** result set, even when the caller
asked for a ``limit``. That way a later, unlimited run is served entirely from
cache instead of re-fetching. ``limit`` only trims the records returned to the
caller.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ct_lens.core.cache import DEFAULT_MAX_AGE, Cache
from ct_lens.core.models import CrtShRecord, ScanSummary
from ct_lens.core.sources.base import CertSource

#: How many example domains to include in a :class:`ScanSummary`.
SAMPLE_SIZE = 10

#: How many issuing CAs to list in a :class:`ScanSummary`.
TOP_ISSUERS = 10


@dataclass(slots=True)
class CollectionResult:
    """The outcome of a collect: the records plus provenance metadata."""

    pattern: str
    records: list[CrtShRecord]
    from_cache: bool
    fetched_at: datetime


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


def collect(
    target: str,
    source: CertSource,
    *,
    cache: Cache | None = None,
    refresh: bool = False,
    max_age: timedelta = DEFAULT_MAX_AGE,
    limit: int | None = None,
) -> CollectionResult:
    """Fetch records for ``target``, using the cache when possible.

    Args:
        target: TLD, domain, or crt.sh pattern (see :func:`normalize_pattern`).
        source: The certificate source to fetch from.
        cache: Optional on-disk cache. ``None`` disables caching entirely.
        refresh: If ``True``, ignore any cached copy and re-fetch (then
            overwrite the cache).
        max_age: Cached data older than this is considered stale and re-fetched.
        limit: Optional cap on the records *returned* (the full set is still
            cached).

    Returns:
        A :class:`CollectionResult` including whether the data came from cache.
    """
    pattern = normalize_pattern(target)

    # 1. Try the cache first (unless the caller forced a refresh).
    if cache is not None and not refresh:
        entry = cache.load(source.name, pattern, max_age=max_age)
        if entry is not None:
            records = [CrtShRecord.from_json(row) for row in entry.records]
            return CollectionResult(
                pattern=pattern,
                records=_apply_limit(records, limit),
                from_cache=True,
                fetched_at=entry.fetched_at,
            )

    # 2. Cache miss (or refresh) -> fetch the FULL set from the source.
    records = source.fetch(pattern)

    # 3. Store the complete result so future runs are served from cache.
    fetched_at = datetime.now(timezone.utc)
    if cache is not None:
        entry = cache.store(source.name, pattern, [r.to_dict() for r in records])
        fetched_at = entry.fetched_at

    return CollectionResult(
        pattern=pattern,
        records=_apply_limit(records, limit),
        from_cache=False,
        fetched_at=fetched_at,
    )


def _apply_limit(records: list[CrtShRecord], limit: int | None) -> list[CrtShRecord]:
    """Return at most ``limit`` records (or all of them when ``limit`` is None)."""
    return records if limit is None else records[:limit]


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


def scan(
    target: str,
    source: CertSource,
    *,
    cache: Cache | None = None,
    refresh: bool = False,
    max_age: timedelta = DEFAULT_MAX_AGE,
    limit: int | None = None,
) -> ScanSummary:
    """Convenience wrapper: :func:`collect` then :func:`summarize_records`."""
    result = collect(target, source, cache=cache, refresh=refresh, max_age=max_age, limit=limit)
    return summarize_records(result.pattern, result.records)
