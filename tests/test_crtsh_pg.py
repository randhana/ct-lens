"""Tests for the crt.sh Postgres source (:mod:`ct_lens.core.sources.crtsh_pg`).

A fake connection/cursor is injected so these tests need neither a database nor
the ``psycopg`` dependency.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from ct_lens.core.sources.crtsh_pg import CrtShPostgresSource, row_to_record


class _FakeCursor:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self.executed: tuple[str, dict[str, Any]] | None = None

    def execute(self, query: str, params: dict[str, Any]) -> None:
        self.executed = (query, params)

    def fetchall(self) -> list[dict[str, Any]]:
        return self._rows

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class _FakeConnection:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self.closed = False
        self.last_cursor: _FakeCursor | None = None

    def cursor(self) -> _FakeCursor:
        self.last_cursor = _FakeCursor(self._rows)
        return self.last_cursor

    def close(self) -> None:
        self.closed = True


def _sample_rows() -> list[dict[str, Any]]:
    return [
        {
            "id": 42,
            "issuer_ca_id": 16418,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "example.lk",
            "name_value": "example.lk\nwww.example.lk",
            "not_before": dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
            "not_after": dt.datetime(2024, 3, 31, tzinfo=dt.timezone.utc),
            "serial_number": "03aa",
            "entry_timestamp": dt.datetime(2024, 1, 1, 10, tzinfo=dt.timezone.utc),
        }
    ]


def test_row_to_record_maps_fields_and_datetimes() -> None:
    record = row_to_record(_sample_rows()[0])
    assert record.id == 42
    assert record.issuer == "Let's Encrypt"
    assert record.domains == ["example.lk", "www.example.lk"]
    # datetimes are rendered as ISO strings for CrtShRecord
    assert record.not_before.startswith("2024-01-01T")


def test_fetch_uses_connection_and_maps_rows() -> None:
    conn = _FakeConnection(_sample_rows())
    source = CrtShPostgresSource(connection=conn)

    records = source.fetch("%.lk", limit=10)

    assert len(records) == 1
    assert records[0].common_name == "example.lk"
    # the pattern and limit were passed as query parameters
    assert conn.last_cursor is not None
    assert conn.last_cursor.executed is not None
    assert conn.last_cursor.executed[1] == {"pattern": "%.lk", "limit": 10}


def test_injected_connection_is_not_closed_by_source() -> None:
    # A caller-provided connection is not "owned" by the source.
    conn = _FakeConnection(_sample_rows())
    source = CrtShPostgresSource(connection=conn)
    source.close()
    assert conn.closed is False
