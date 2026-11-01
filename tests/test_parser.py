"""Tests for :mod:`ct_lens.core.parser`."""

from __future__ import annotations

from datetime import timezone

from ct_lens.core.models import CrtShRecord
from ct_lens.core.parser import (
    build_dataset,
    deduplicate,
    parse_record,
    parse_timestamp,
)


def test_parse_timestamp_naive_is_treated_as_utc() -> None:
    dt = parse_timestamp("2024-01-15T09:00:00")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert (dt.year, dt.month, dt.day) == (2024, 1, 15)


def test_parse_timestamp_handles_fractional_and_z() -> None:
    assert parse_timestamp("2024-02-20T12:30:00.000") is not None
    assert parse_timestamp("2024-02-20T12:30:00Z") is not None


def test_parse_timestamp_bad_input_returns_none() -> None:
    assert parse_timestamp("") is None
    assert parse_timestamp("not-a-date") is None


def test_parse_record_computes_lifetime(crtsh_sample: list[dict[str, object]]) -> None:
    record = CrtShRecord.from_json(crtsh_sample[0])  # 90-day Let's Encrypt cert
    cert = parse_record(record)
    assert cert.lifetime_days == 90
    assert cert.common_name == "example.lk"
    assert cert.is_wildcard is False


def test_parse_record_detects_wildcard(crtsh_sample: list[dict[str, object]]) -> None:
    record = CrtShRecord.from_json(crtsh_sample[2])  # contains *.gov.lk
    cert = parse_record(record)
    assert cert.is_wildcard is True


def test_deduplicate_collapses_same_issuer_and_serial() -> None:
    rows = [
        {"id": 1, "issuer_name": "O=CA", "serial_number": "AA", "not_before": "", "not_after": ""},
        # same issuer + serial = pre-cert/leaf pair -> must collapse to one
        {"id": 2, "issuer_name": "O=CA", "serial_number": "AA", "not_before": "", "not_after": ""},
        {"id": 3, "issuer_name": "O=CA", "serial_number": "BB", "not_before": "", "not_after": ""},
    ]
    certs = [parse_record(CrtShRecord.from_json(r)) for r in rows]
    unique = deduplicate(certs)
    assert len(unique) == 2
    # First occurrence (id=1) is kept, not the duplicate id=2.
    assert unique[0].cert_id == 1


def test_build_dataset_dedupe_toggle(crtsh_sample: list[dict[str, object]]) -> None:
    records = [CrtShRecord.from_json(r) for r in crtsh_sample]
    # The sample has 4 distinct serials, so dedupe does not drop anything here.
    assert len(build_dataset(records, dedupe=True)) == 4
    assert len(build_dataset(records, dedupe=False)) == 4
