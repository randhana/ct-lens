"""Parse raw crt.sh records into the normalised :class:`Certificate` model.

Responsibilities (README §3.2):
    * parse the crt.sh date strings into ``datetime`` objects,
    * carry through domains / issuer / serial,
    * **de-duplicate pre-certificates against their final certificate** so that
      counts (and therefore CA-share statistics) are not inflated.

Signature algorithm and key type/size are *not* available in the crt.sh JSON
index; they are added later by the optional :mod:`ct_lens.core.enrich` step.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ct_lens.core.models import Certificate, CrtShRecord


def parse_timestamp(value: str) -> datetime | None:
    """Parse a crt.sh timestamp into a timezone-aware UTC ``datetime``.

    crt.sh emits ISO-8601 strings without a timezone, e.g.
    ``"2024-01-15T09:00:00"`` or ``"2024-01-15T10:00:00.000"``. These are UTC,
    so we attach UTC explicitly. Unparseable or empty values return ``None``
    rather than raising — a single bad row must never abort a whole dataset.

    Args:
        value: The raw timestamp string from a crt.sh record.

    Returns:
        A UTC-aware ``datetime``, or ``None`` if it could not be parsed.
    """
    value = value.strip()
    if not value:
        return None
    # Python 3.10's fromisoformat does not accept a trailing "Z"; normalise it.
    if value.endswith("Z"):
        value = value[:-1]
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    # Treat naive timestamps as UTC (crt.sh stores UTC).
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_record(record: CrtShRecord) -> Certificate:
    """Convert a single :class:`CrtShRecord` into a normalised :class:`Certificate`."""
    return Certificate(
        cert_id=record.id,
        serial_number=record.serial_number,
        issuer=record.issuer,
        issuer_name=record.issuer_name,
        common_name=record.common_name,
        domains=tuple(record.domains),
        not_before=parse_timestamp(record.not_before),
        not_after=parse_timestamp(record.not_after),
        entry_timestamp=parse_timestamp(record.entry_timestamp),
    )


def deduplicate(certificates: list[Certificate]) -> list[Certificate]:
    """Collapse pre-certificate / final-certificate pairs.

    Keeps the first occurrence of each :attr:`Certificate.dedupe_key` and
    preserves input order (crt.sh returns newest-first, which we keep).
    """
    seen: set[tuple[str, str]] = set()
    unique: list[Certificate] = []
    for certificate in certificates:
        key = certificate.dedupe_key
        if key in seen:
            continue
        seen.add(key)
        unique.append(certificate)
    return unique


def build_dataset(records: list[CrtShRecord], *, dedupe: bool = True) -> list[Certificate]:
    """Parse and (optionally) de-duplicate raw records into the dataset.

    Args:
        records: Raw crt.sh records (typically from the collector/cache).
        dedupe: When ``True`` (default), collapse pre-cert/leaf duplicates.

    Returns:
        The normalised list of certificates.
    """
    certificates = [parse_record(record) for record in records]
    if dedupe:
        certificates = deduplicate(certificates)
    return certificates
