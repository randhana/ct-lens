"""Tests for the data models in :mod:`ct_lens.core.models`."""

from __future__ import annotations

from ct_lens.core.models import CrtShRecord, issuer_organization


def test_issuer_organization_extracts_o_component() -> None:
    assert issuer_organization("C=US, O=Let's Encrypt, CN=R3") == "Let's Encrypt"


def test_issuer_organization_falls_back_to_full_string() -> None:
    # No O= component -> return the original string rather than losing it.
    assert issuer_organization("CN=Self-signed test CA") == "CN=Self-signed test CA"


def test_record_from_json_is_tolerant_of_missing_keys() -> None:
    record = CrtShRecord.from_json({"id": 5})
    assert record.id == 5
    assert record.issuer_name == ""
    assert record.issuer_ca_id == 0


def test_record_domains_splits_sans_and_dedupes(crtsh_sample: list[dict[str, object]]) -> None:
    # Row 0 has "example.lk" and "www.example.lk" in name_value.
    record = CrtShRecord.from_json(crtsh_sample[0])
    assert record.domains == ["example.lk", "www.example.lk"]


def test_record_domains_lowercases_and_preserves_wildcards(
    crtsh_sample: list[dict[str, object]],
) -> None:
    # Row 2 contains a wildcard "*.gov.lk" which must be preserved.
    record = CrtShRecord.from_json(crtsh_sample[2])
    assert "*.gov.lk" in record.domains


def test_record_issuer_property_uses_organization(
    crtsh_sample: list[dict[str, object]],
) -> None:
    record = CrtShRecord.from_json(crtsh_sample[0])
    assert record.issuer == "Let's Encrypt"
