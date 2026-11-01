"""crt.sh PostgreSQL certificate source — for the *complete* dataset.

The crt.sh JSON endpoint is convenient but caps large results and times out on
broad queries. crt.sh also publishes the same data as a public, read-only
PostgreSQL database (``postgresql://guest@crt.sh:5432/certwatch``), which can
return the full set for a TLD with a single query.

This source is **optional**: it needs the ``postgres`` extra
(``pip install "ct-lens[postgres]"``) and ``psycopg`` is imported lazily so the
rest of the tool works without it. It is still read-only and still contacts only
crt.sh — never a target server.

Query notes:
    * Suffix matching uses the standard crt.sh trick of comparing
      ``reverse(lower(name_value))`` against ``reverse(pattern)`` so a normal
      B-tree index on the reversed name can be used.
    * SAN names are aggregated per certificate into a newline-separated
      ``name_value`` to mirror the JSON endpoint's shape.
    * A ``statement_timeout`` is set so a slow query fails cleanly instead of
      hanging forever.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from ct_lens.core.models import CrtShRecord
from ct_lens.core.sources.base import CertSource

#: Public, read-only crt.sh database (guest account, no password).
DEFAULT_CONNINFO: Final = "postgresql://guest@crt.sh:5432/certwatch"

#: Default server-side statement timeout (ms). crt.sh is shared; be polite.
DEFAULT_STATEMENT_TIMEOUT_MS: Final = 120_000

#: Upper bound applied when the caller does not pass an explicit ``limit``.
_HARD_LIMIT: Final = 1_000_000

#: The query. One row per certificate, with SAN names aggregated.
_QUERY: Final = """
SELECT c.id                                        AS id,
       c.issuer_ca_id                              AS issuer_ca_id,
       ca.name                                     AS issuer_name,
       x509_commonname(c.certificate)              AS common_name,
       string_agg(DISTINCT cai.name_value, E'\\n')  AS name_value,
       x509_notbefore(c.certificate)               AS not_before,
       x509_notafter(c.certificate)                AS not_after,
       encode(x509_serialnumber(c.certificate), 'hex') AS serial_number,
       min(ctle.entry_timestamp)                   AS entry_timestamp
FROM certificate c
JOIN ca ON ca.id = c.issuer_ca_id
JOIN certificate_and_identities cai ON cai.certificate_id = c.id
LEFT JOIN ct_log_entry ctle ON ctle.certificate_id = c.id
WHERE cai.name_type = 'san:dNSName'
  AND reverse(lower(cai.name_value)) LIKE reverse(lower(%(pattern)s))
GROUP BY c.id, c.issuer_ca_id, ca.name, c.certificate
LIMIT %(limit)s
"""


def _to_str(value: object) -> str:
    """Render a DB value as a string suitable for :class:`CrtShRecord`."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def row_to_record(row: dict[str, Any]) -> CrtShRecord:
    """Map one query row (a dict) to a :class:`CrtShRecord`."""
    return CrtShRecord.from_json(
        {
            "id": row.get("id", 0),
            "issuer_ca_id": row.get("issuer_ca_id", 0),
            "issuer_name": _to_str(row.get("issuer_name")),
            "common_name": _to_str(row.get("common_name")),
            "name_value": _to_str(row.get("name_value")),
            "not_before": _to_str(row.get("not_before")),
            "not_after": _to_str(row.get("not_after")),
            "serial_number": _to_str(row.get("serial_number")),
            "entry_timestamp": _to_str(row.get("entry_timestamp")),
        }
    )


class CrtShPostgresSource(CertSource):
    """Fetch the complete certificate set for a pattern from crt.sh's database."""

    name = "crtsh-postgres"

    def __init__(
        self,
        conninfo: str = DEFAULT_CONNINFO,
        *,
        statement_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
        connection: Any | None = None,
    ) -> None:
        """Create a Postgres source.

        Args:
            conninfo: libpq connection string (defaults to the public crt.sh DB).
            statement_timeout_ms: Server-side query timeout in milliseconds.
            connection: An already-open DB connection (used by tests to inject a
                fake). When omitted, one is opened lazily on first fetch.
        """
        self._conninfo = conninfo
        self._statement_timeout_ms = statement_timeout_ms
        self._connection = connection
        self._owns_connection = connection is None

    def _connect(self) -> Any:
        """Open a psycopg connection (imported lazily) with dict rows."""
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - exercised via patched import
            raise RuntimeError(
                "the Postgres source needs the 'postgres' extra; install it with:\n"
                '    pip install "ct-lens[postgres]"'
            ) from exc
        options = f"-c statement_timeout={self._statement_timeout_ms}"
        return psycopg.connect(self._conninfo, options=options, row_factory=dict_row)

    def fetch(self, pattern: str, *, limit: int | None = None) -> list[CrtShRecord]:
        """Fetch records for ``pattern`` from the crt.sh database."""
        connection = self._connection or self._connect()
        if self._connection is None:
            self._connection = connection
        params = {"pattern": pattern, "limit": limit if limit is not None else _HARD_LIMIT}
        with connection.cursor() as cursor:
            cursor.execute(_QUERY, params)
            rows = cursor.fetchall()
        return [row_to_record(row) for row in rows]

    def close(self) -> None:
        """Close the connection if this source opened it."""
        if self._owns_connection and self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> CrtShPostgresSource:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
