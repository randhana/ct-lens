"""Typed data models shared across the ct-lens engine.

* :class:`CrtShRecord` — a faithful, thin view of one crt.sh JSON row.
* :class:`ScanSummary` — the quick summary produced by the Phase 1 spike.
* :class:`Certificate` — the fully-normalised certificate used from Phase 3 on
  (parsed dates, computed lifetime, wildcard flag, optional key/signature info).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


def issuer_organization(issuer_name: str) -> str:
    """Extract a human-friendly CA name from a crt.sh ``issuer_name`` string.

    crt.sh issuer names look like an X.509 Distinguished Name, e.g.::

        "C=US, O=Let's Encrypt, CN=R3"

    The ``O=`` (Organization) component is the most useful label for grouping
    certificates by Certificate Authority, so we return it when present. If no
    ``O=`` component exists we fall back to the full string so nothing is lost.

    Args:
        issuer_name: The raw ``issuer_name`` field from a crt.sh record.

    Returns:
        The organization name, or the original string if none could be found.
    """
    for part in issuer_name.split(","):
        key, _, value = part.strip().partition("=")
        if key.upper() == "O" and value:
            return value.strip()
    return issuer_name.strip()


@dataclass(frozen=True, slots=True)
class CrtShRecord:
    """A single row returned by the crt.sh JSON endpoint.

    This is an intentionally thin, faithful representation of the upstream JSON.
    Normalisation (parsing dates, extracting key sizes, de-duplicating
    pre-certificates) happens later in the pipeline, not here.
    """

    id: int
    issuer_ca_id: int
    issuer_name: str
    common_name: str
    name_value: str
    entry_timestamp: str
    not_before: str
    not_after: str
    serial_number: str

    @classmethod
    def from_json(cls, row: dict[str, object]) -> CrtShRecord:
        """Build a record from one crt.sh JSON object, tolerating missing keys."""

        def _str(key: str) -> str:
            value = row.get(key, "")
            return str(value) if value is not None else ""

        def _int(key: str) -> int:
            value = row.get(key, 0)
            if isinstance(value, bool):  # bool is a subclass of int — handle explicitly
                return int(value)
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str):
                try:
                    return int(value)
                except ValueError:
                    return 0
            return 0

        return cls(
            id=_int("id"),
            issuer_ca_id=_int("issuer_ca_id"),
            issuer_name=_str("issuer_name"),
            common_name=_str("common_name"),
            name_value=_str("name_value"),
            entry_timestamp=_str("entry_timestamp"),
            not_before=_str("not_before"),
            not_after=_str("not_after"),
            serial_number=_str("serial_number"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise back to a crt.sh-shaped dict (used by the on-disk cache).

        The keys match crt.sh's JSON field names, so a round-trip through
        :meth:`to_dict` and :meth:`from_json` reproduces an equivalent record.
        """
        return {
            "id": self.id,
            "issuer_ca_id": self.issuer_ca_id,
            "issuer_name": self.issuer_name,
            "common_name": self.common_name,
            "name_value": self.name_value,
            "entry_timestamp": self.entry_timestamp,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial_number": self.serial_number,
        }

    @property
    def issuer(self) -> str:
        """Human-friendly CA name (the ``O=`` component when available)."""
        return issuer_organization(self.issuer_name)

    @property
    def domains(self) -> list[str]:
        """All domain names in this record (``name_value`` is newline-separated).

        Returns a de-duplicated, lower-cased list. A leading ``*.`` wildcard is
        preserved because it is meaningful for certificate analysis.
        """
        seen: dict[str, None] = {}
        for raw in self.name_value.splitlines():
            name = raw.strip().lower()
            if name:
                seen.setdefault(name, None)
        return list(seen)


@dataclass(slots=True)
class ScanSummary:
    """A quick summary of a scan — the output of the Phase 1 spike.

    Attributes:
        pattern: The crt.sh query pattern that was scanned (e.g. ``%.lk``).
        total_records: Number of CT log records returned.
        unique_domains: Number of distinct domain names seen.
        top_issuers: ``(ca_name, count)`` pairs, most frequent first.
        sample_domains: A handful of example domains for a sanity check.
    """

    pattern: str
    total_records: int
    unique_domains: int
    top_issuers: list[tuple[str, int]] = field(default_factory=list)
    sample_domains: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Certificate:
    """A normalised certificate — the unit of the ct-lens dataset.

    This is the clean, analysis-ready representation produced from a
    :class:`CrtShRecord` by :mod:`ct_lens.core.parser`. Dates are parsed into
    ``datetime`` objects and the certificate lifetime is derived from them.

    The ``signature_algorithm`` / ``key_type`` / ``key_size`` fields are
    *optional enrichment*: crt.sh's JSON index does not include them, so they
    are only populated when the raw certificate is downloaded and parsed (see
    :mod:`ct_lens.core.enrich`). They stay ``None`` otherwise.
    """

    cert_id: int
    serial_number: str
    issuer: str  # human-friendly CA name (the O= component)
    issuer_name: str  # full issuer DN string
    common_name: str
    domains: tuple[str, ...]
    not_before: datetime | None
    not_after: datetime | None
    entry_timestamp: datetime | None
    signature_algorithm: str | None = None
    key_type: str | None = None
    key_size: int | None = None

    @property
    def lifetime_days(self) -> int | None:
        """Validity period in whole days, or ``None`` if dates are missing."""
        if self.not_before is None or self.not_after is None:
            return None
        return (self.not_after - self.not_before).days

    @property
    def is_wildcard(self) -> bool:
        """True if any covered domain is a wildcard (``*.example.lk``)."""
        return any(domain.startswith("*.") for domain in self.domains)

    @property
    def dedupe_key(self) -> tuple[str, str]:
        """Key that collapses a pre-certificate and its final certificate.

        crt.sh logs a *pre-certificate* and the *final certificate* as two
        separate rows that share the same issuer and serial number. Counting
        both would inflate CA-share statistics, so de-duplication groups on
        ``(issuer_name, serial_number)``. When no serial is present we fall back
        to the crt.sh id so distinct rows are never silently merged.
        """
        if self.serial_number:
            return (self.issuer_name, self.serial_number.lower())
        return ("__id__", str(self.cert_id))
