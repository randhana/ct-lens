"""Optional enrichment: fill in signature algorithm and key type/size.

crt.sh's JSON index does not expose the signature algorithm or the public-key
details. To add them (README §3.2) we must download the actual certificate and
parse it with the ``cryptography`` library.

This is deliberately **opt-in**:
    * it costs one extra crt.sh request per certificate, and
    * it needs the optional ``cryptography`` dependency (``pip install
      "ct-lens[analysis]"``).

``cryptography`` is imported lazily so that the rest of the engine — scanning,
caching, exporting the base dataset — works without it. Enrichment is also
best-effort: a certificate that fails to download or parse is returned
unchanged rather than aborting the run.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import httpx

from ct_lens.core.models import Certificate

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from ct_lens.core.sources.crtsh_json import CrtShJsonSource

#: Default polite delay between per-certificate downloads (seconds).
DEFAULT_INTERVAL_S = 0.5


class EnrichmentUnavailableError(RuntimeError):
    """Raised when enrichment is requested but ``cryptography`` is not installed."""


def _load_cryptography() -> Any:
    """Import ``cryptography.x509`` lazily, with a helpful error if it is missing."""
    try:
        from cryptography import x509
    except ImportError as exc:  # pragma: no cover - exercised via a patched import
        raise EnrichmentUnavailableError(
            "certificate enrichment requires the 'analysis' extra; install it with:\n"
            '    pip install "ct-lens[analysis]"'
        ) from exc
    return x509


def _classify_key(public_key: Any) -> tuple[str | None, int | None]:
    """Return a ``(key_type, key_size)`` label for a certificate's public key."""
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", None
    return type(public_key).__name__, None


def extract_fields(cert_bytes: bytes) -> tuple[str | None, str | None, int | None]:
    """Parse raw certificate bytes into ``(signature_algorithm, key_type, key_size)``.

    Accepts either PEM or DER encoding. This function is pure (no network), which
    makes it straightforward to test with a locally generated certificate.
    """
    x509 = _load_cryptography()
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        cert = x509.load_der_x509_certificate(cert_bytes)

    # The OID's name is the canonical signature-algorithm label, e.g.
    # "sha256WithRSAEncryption" or "ecdsa-with-SHA384".
    signature_algorithm = getattr(cert.signature_algorithm_oid, "_name", None)
    key_type, key_size = _classify_key(cert.public_key())
    return signature_algorithm, key_type, key_size


def enrich_certificate(certificate: Certificate, cert_bytes: bytes) -> Certificate:
    """Return a copy of ``certificate`` with key/signature fields filled in."""
    signature_algorithm, key_type, key_size = extract_fields(cert_bytes)
    return replace(
        certificate,
        signature_algorithm=signature_algorithm,
        key_type=key_type,
        key_size=key_size,
    )


def enrich(
    certificates: list[Certificate],
    source: CrtShJsonSource,
    *,
    limit: int | None = None,
    interval_s: float = DEFAULT_INTERVAL_S,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[Certificate]:
    """Download and parse each certificate to add signature/key details.

    Args:
        certificates: The dataset to enrich.
        source: A crt.sh source able to download raw certificates.
        limit: Enrich at most this many certificates (the rest are returned
            unchanged). ``None`` enriches all — use with care on large datasets.
        interval_s: Polite delay between downloads, so we do not hammer crt.sh.
        on_progress: Optional ``callback(done, total)`` for a progress display.

    Returns:
        A new list of certificates, enriched where possible.
    """
    to_process = certificates if limit is None else certificates[:limit]
    total = len(to_process)
    enriched: list[Certificate] = []

    for index, certificate in enumerate(to_process, start=1):
        try:
            cert_bytes = source.fetch_certificate_bytes(certificate.cert_id)
            enriched.append(enrich_certificate(certificate, cert_bytes))
        except (httpx.HTTPError, ValueError):
            # Best-effort: keep the un-enriched certificate and move on.
            enriched.append(certificate)
        if on_progress is not None:
            on_progress(index, total)
        if interval_s > 0 and index < total:
            time.sleep(interval_s)

    # Any certificates beyond the limit are returned as-is.
    enriched.extend(certificates[total:])
    return enriched
