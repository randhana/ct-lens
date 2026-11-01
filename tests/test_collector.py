"""Tests for :mod:`ct_lens.core.collector`."""

from __future__ import annotations

from pathlib import Path

import pytest

from ct_lens.core.cache import Cache
from ct_lens.core.collector import collect, normalize_pattern, summarize_records
from ct_lens.core.models import CrtShRecord
from ct_lens.core.sources.base import CertSource


class FakeSource(CertSource):
    """An in-memory source that records how many times ``fetch`` was called."""

    name = "fake"

    def __init__(self, records: list[CrtShRecord]) -> None:
        self._records = records
        self.calls = 0

    def fetch(self, pattern: str, *, limit: int | None = None) -> list[CrtShRecord]:
        self.calls += 1
        return self._records if limit is None else self._records[:limit]


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        (".lk", "%.lk"),
        ("lk", "%.lk"),
        ("example.com", "%.example.com"),
        ("%.lk", "%.lk"),  # explicit pattern passes through untouched
        ("  .LK  ", "%.lk"),  # trimmed and lower-cased
    ],
)
def test_normalize_pattern(target: str, expected: str) -> None:
    assert normalize_pattern(target) == expected


def test_normalize_pattern_rejects_empty() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        normalize_pattern("   ")


def test_summarize_records_counts_and_ranks(crtsh_sample: list[dict[str, object]]) -> None:
    records = [CrtShRecord.from_json(row) for row in crtsh_sample]
    summary = summarize_records("%.lk", records)

    assert summary.total_records == 4
    # Distinct domains: example.lk, www.example.lk, shop.example.lk, gov.lk,
    # *.gov.lk, vpn-staging.internal.example.lk = 6
    assert summary.unique_domains == 6

    # Let's Encrypt issued 2 of the 4 records -> it must rank first.
    assert summary.top_issuers[0] == ("Let's Encrypt", 2)


def test_summarize_records_handles_empty_input() -> None:
    summary = summarize_records("%.lk", [])
    assert summary.total_records == 0
    assert summary.unique_domains == 0
    assert summary.top_issuers == []
    assert summary.sample_domains == []


# --------------------------------------------------------------------------- #
# collect() + cache behaviour
# --------------------------------------------------------------------------- #


def _records(crtsh_sample: list[dict[str, object]]) -> list[CrtShRecord]:
    return [CrtShRecord.from_json(row) for row in crtsh_sample]


def test_collect_without_cache_always_fetches(crtsh_sample: list[dict[str, object]]) -> None:
    source = FakeSource(_records(crtsh_sample))

    result = collect(".lk", source, cache=None)

    assert result.from_cache is False
    assert source.calls == 1
    assert len(result.records) == 4


def test_collect_second_run_is_served_from_cache(
    crtsh_sample: list[dict[str, object]], tmp_path: Path
) -> None:
    source = FakeSource(_records(crtsh_sample))
    cache = Cache(tmp_path)

    first = collect(".lk", source, cache=cache)
    second = collect(".lk", source, cache=cache)

    assert first.from_cache is False
    assert second.from_cache is True
    # crt.sh was only hit once; the cache answered the second time.
    assert source.calls == 1
    assert len(second.records) == 4


def test_collect_refresh_bypasses_cache(
    crtsh_sample: list[dict[str, object]], tmp_path: Path
) -> None:
    source = FakeSource(_records(crtsh_sample))
    cache = Cache(tmp_path)

    collect(".lk", source, cache=cache)
    result = collect(".lk", source, cache=cache, refresh=True)

    assert result.from_cache is False
    assert source.calls == 2


def test_collect_caches_full_set_even_with_limit(
    crtsh_sample: list[dict[str, object]], tmp_path: Path
) -> None:
    source = FakeSource(_records(crtsh_sample))
    cache = Cache(tmp_path)

    # First run asks for only 1 record but the FULL set must still be cached...
    limited = collect(".lk", source, cache=cache, limit=1)
    assert len(limited.records) == 1

    # ...so a later unlimited run is served entirely from cache (no re-fetch).
    full = collect(".lk", source, cache=cache)
    assert full.from_cache is True
    assert len(full.records) == 4
    assert source.calls == 1
