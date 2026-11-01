"""Tests for the optional enrichment step (:mod:`ct_lens.core.enrich`).

A real certificate is generated in-process with ``cryptography`` so the parse
path is exercised deterministically and without any network access.
"""

from __future__ import annotations

import datetime as dt

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ct_lens.core.enrich import enrich, enrich_certificate, extract_fields
from ct_lens.core.models import Certificate
from ct_lens.core.sources.crtsh_json import CRTSH_URL, CrtShJsonSource


def _self_signed_rsa_pem(bits: int = 2048) -> bytes:
    """Create a throwaway self-signed RSA certificate and return it as PEM bytes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.lk")])
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _blank_cert(cert_id: int = 1001) -> Certificate:
    return Certificate(
        cert_id=cert_id,
        serial_number="AA",
        issuer="Test",
        issuer_name="O=Test",
        common_name="test.example.lk",
        domains=("test.example.lk",),
        not_before=None,
        not_after=None,
        entry_timestamp=None,
    )


def test_extract_fields_from_rsa_cert() -> None:
    sig, key_type, key_size = extract_fields(_self_signed_rsa_pem(2048))
    assert key_type == "RSA"
    assert key_size == 2048
    assert sig is not None and "RSA" in sig  # e.g. "sha256WithRSAEncryption"


def test_enrich_certificate_fills_fields() -> None:
    enriched = enrich_certificate(_blank_cert(), _self_signed_rsa_pem())
    assert enriched.key_type == "RSA"
    assert enriched.key_size == 2048
    # original is unchanged (frozen dataclass -> a copy is returned)
    assert _blank_cert().key_type is None


@respx.mock
def test_enrich_downloads_and_fills(monkeypatch: pytest.MonkeyPatch) -> None:
    pem = _self_signed_rsa_pem()
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, content=pem))

    with CrtShJsonSource() as source:
        result = enrich([_blank_cert()], source, interval_s=0.0)

    assert result[0].key_type == "RSA"


@respx.mock
def test_enrich_is_best_effort_on_download_failure() -> None:
    respx.get(CRTSH_URL).mock(side_effect=httpx.ConnectError("boom"))

    with CrtShJsonSource() as source:
        result = enrich([_blank_cert()], source, interval_s=0.0)

    # Download failed -> certificate returned unchanged, no crash.
    assert result[0].key_type is None


@respx.mock
def test_enrich_respects_limit() -> None:
    pem = _self_signed_rsa_pem()
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, content=pem))

    certs = [_blank_cert(1), _blank_cert(2), _blank_cert(3)]
    with CrtShJsonSource() as source:
        result = enrich(certs, source, limit=1, interval_s=0.0)

    assert len(result) == 3
    assert result[0].key_type == "RSA"  # first enriched
    assert result[1].key_type is None  # beyond the limit -> untouched
