"""Tests for :mod:`ct_lens.core.analysis`."""

from __future__ import annotations

from dataclasses import replace

from ct_lens.core.analysis import analyze, ca_shares, lifetime_stats
from ct_lens.core.models import Certificate, CrtShRecord
from ct_lens.core.parser import build_dataset


def _dataset(crtsh_sample: list[dict[str, object]]) -> list[Certificate]:
    return build_dataset([CrtShRecord.from_json(r) for r in crtsh_sample])


def test_ca_shares_ranked_and_normalised(crtsh_sample: list[dict[str, object]]) -> None:
    shares = ca_shares(_dataset(crtsh_sample))
    # Let's Encrypt issued 2 of 4 -> 50% and ranked first.
    assert shares[0].issuer == "Let's Encrypt"
    assert shares[0].count == 2
    assert abs(shares[0].share - 0.5) < 1e-9
    assert abs(sum(s.share for s in shares) - 1.0) < 1e-9


def test_lifetime_stats_and_buckets(crtsh_sample: list[dict[str, object]]) -> None:
    stats = lifetime_stats(_dataset(crtsh_sample))
    # Lifetimes in the sample: 90, 90, 366, 365 days.
    assert stats.count == 4
    assert stats.min_days == 90
    assert stats.max_days == 366
    bucket = dict(stats.buckets)
    assert bucket["48-90 days"] == 2  # the two 90-day LE certs
    assert bucket[">397 days"] == 0
    assert bucket["181-397 days"] == 2  # the 365 & 366 day certs


def test_lifetime_stats_empty() -> None:
    stats = lifetime_stats([])
    assert stats.count == 0
    assert stats.median_days is None


def test_analyze_full_report(crtsh_sample: list[dict[str, object]]) -> None:
    certs = _dataset(crtsh_sample)
    report = analyze("%.lk", certs)

    assert report.total_certificates == 4
    assert report.wildcard_count == 1  # *.gov.lk
    assert report.ca_concentration_top1 == 0.5
    # issuance spans several months -> grouped and sorted ascending
    periods = [p.period for p in report.issuance_by_month]
    assert periods == sorted(periods)
    # no enrichment -> empty key/sig distributions
    assert report.key_types == []


def test_analyze_uses_enriched_fields(crtsh_sample: list[dict[str, object]]) -> None:
    certs = _dataset(crtsh_sample)
    certs = [
        replace(c, key_type="RSA", signature_algorithm="sha256WithRSAEncryption") for c in certs
    ]
    report = analyze("%.lk", certs)
    assert report.key_types == [("RSA", 4)]
    assert report.signature_algorithms[0][0] == "sha256WithRSAEncryption"
