"""Tests for :mod:`ct_lens.core.findings`."""

from __future__ import annotations

from ct_lens.core.findings import (
    detect_exposed_hosts,
    detect_lookalikes,
    detect_suspicious_issuance,
    find_all,
    levenshtein,
    registrable_label,
)
from ct_lens.core.models import Certificate


def _cert(
    cert_id: int, domains: tuple[str, ...], issuer_name: str = "C=US, O=Let's Encrypt"
) -> Certificate:
    return Certificate(
        cert_id=cert_id,
        serial_number=str(cert_id),
        issuer="Let's Encrypt" if "O=" in issuer_name else issuer_name,
        issuer_name=issuer_name,
        common_name=domains[0],
        domains=domains,
        not_before=None,
        not_after=None,
        entry_timestamp=None,
    )


def test_levenshtein_basic() -> None:
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("bankofceylon", "bankofceylom") == 1


def test_registrable_label_handles_public_2ld() -> None:
    assert registrable_label("www.bankofceylon.lk") == "bankofceylon"
    assert registrable_label("mail.treasury.gov.lk") == "treasury"
    assert registrable_label("*.gov.lk") == "gov"


def test_detect_lookalikes_homoglyph() -> None:
    certs = [
        _cert(1, ("bankofceylon.lk",)),
        _cert(1, ("bankofceylon.lk",)),  # make it a high-volume anchor
        _cert(2, ("bankofceyl0n.lk",)),  # zero instead of o -> lookalike
    ]
    results = detect_lookalikes(certs)
    assert any(f.domain == "bankofceyl0n.lk" and f.reference == "bankofceylon" for f in results)


def test_detect_exposed_hosts() -> None:
    certs = [_cert(3, ("vpn-staging.internal.example.lk",))]
    results = detect_exposed_hosts(certs)
    assert len(results) == 1
    assert results[0].category == "exposed-host"


def test_detect_suspicious_issuance_flags_self_signed() -> None:
    certs = [
        _cert(4, ("secure.example.lk",), issuer_name="CN=Self-signed test CA"),
        _cert(5, ("ok.example.lk",), issuer_name="C=US, O=Let's Encrypt, CN=R3"),
    ]
    results = detect_suspicious_issuance(certs)
    assert len(results) == 1
    assert results[0].cert_id == 4


def test_find_all_sorted_and_anonymized() -> None:
    certs = [
        _cert(1, ("bankofceylon.lk",)),
        _cert(1, ("bankofceylon.lk",)),
        _cert(2, ("bankofceyl0n.lk",)),
        _cert(3, ("vpn.internal.acme.lk",)),
    ]
    results = find_all(certs, anonymize=True)
    # high severity (lookalike) must come before medium (exposed-host)
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    severities = [f.severity for f in results]
    assert severities == sorted(severities, key=lambda s: rank[s])
    # anonymised: organisation label is masked
    exposed = next(f for f in results if f.category == "exposed-host")
    assert "acme" not in exposed.domain
    assert "a***" in exposed.domain
