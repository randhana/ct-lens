"""Export a normalised certificate dataset to CSV and JSON.

Uses only the Python standard library so that producing the machine-readable
dataset (README §3.5) does not require the heavier analysis/plotting extras.

The CSV is one row per certificate with flat, spreadsheet-friendly columns; the
JSON is a list of objects preserving structured types (domains as a list, dates
as ISO-8601 strings).
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from ct_lens.core.models import Certificate

#: Column order for the exported dataset (CSV header and JSON key order).
FIELDNAMES: list[str] = [
    "cert_id",
    "serial_number",
    "issuer",
    "issuer_name",
    "common_name",
    "domains",
    "not_before",
    "not_after",
    "entry_timestamp",
    "lifetime_days",
    "is_wildcard",
    "signature_algorithm",
    "key_type",
    "key_size",
]


def _iso(value: datetime | None) -> str | None:
    """Render a datetime as an ISO-8601 string (or ``None``)."""
    return value.isoformat() if value is not None else None


def to_record(certificate: Certificate) -> dict[str, object]:
    """Convert a :class:`Certificate` to a JSON-friendly dict (domains as list)."""
    return {
        "cert_id": certificate.cert_id,
        "serial_number": certificate.serial_number,
        "issuer": certificate.issuer,
        "issuer_name": certificate.issuer_name,
        "common_name": certificate.common_name,
        "domains": list(certificate.domains),
        "not_before": _iso(certificate.not_before),
        "not_after": _iso(certificate.not_after),
        "entry_timestamp": _iso(certificate.entry_timestamp),
        "lifetime_days": certificate.lifetime_days,
        "is_wildcard": certificate.is_wildcard,
        "signature_algorithm": certificate.signature_algorithm,
        "key_type": certificate.key_type,
        "key_size": certificate.key_size,
    }


def _to_csv_row(certificate: Certificate) -> dict[str, object]:
    """Like :func:`to_record` but flattens ``domains`` to a space-joined string."""
    row = to_record(certificate)
    row["domains"] = " ".join(certificate.domains)
    return row


def write_csv(certificates: list[Certificate], path: Path) -> Path:
    """Write the dataset to ``path`` as CSV. Returns the path written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for certificate in certificates:
            writer.writerow(_to_csv_row(certificate))
    return path


def write_json(certificates: list[Certificate], path: Path) -> Path:
    """Write the dataset to ``path`` as a JSON array. Returns the path written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [to_record(certificate) for certificate in certificates]
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return path
