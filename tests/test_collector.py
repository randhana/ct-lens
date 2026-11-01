"""Tests for :mod:`ct_lens.core.collector`."""

from __future__ import annotations

import pytest

from ct_lens.core.collector import normalize_pattern, summarize_records
from ct_lens.core.models import CrtShRecord


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
