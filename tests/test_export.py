"""Tests for :mod:`ct_lens.core.export`."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ct_lens.core.models import Certificate, CrtShRecord
from ct_lens.core.parser import build_dataset


def _dataset(crtsh_sample: list[dict[str, object]]) -> list[Certificate]:
    return build_dataset([CrtShRecord.from_json(r) for r in crtsh_sample])


def test_write_csv_has_header_and_rows(
    crtsh_sample: list[dict[str, object]], tmp_path: Path
) -> None:
    from ct_lens.core.export import FIELDNAMES, write_csv

    path = write_csv(_dataset(crtsh_sample), tmp_path / "dataset.csv")
    rows = list(csv.DictReader(path.open(encoding="utf-8")))

    assert len(rows) == 4
    assert list(rows[0].keys()) == FIELDNAMES
    # domains are space-joined in CSV
    assert "example.lk" in rows[0]["domains"]
    assert rows[0]["lifetime_days"] == "90"


def test_write_json_preserves_structure(
    crtsh_sample: list[dict[str, object]], tmp_path: Path
) -> None:
    from ct_lens.core.export import write_json

    path = write_json(_dataset(crtsh_sample), tmp_path / "dataset.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    assert len(data) == 4
    # domains are a real list in JSON
    assert data[0]["domains"] == ["example.lk", "www.example.lk"]
    assert data[0]["is_wildcard"] is False
    # un-enriched fields are null
    assert data[0]["signature_algorithm"] is None


def test_export_creates_missing_directory(
    crtsh_sample: list[dict[str, object]], tmp_path: Path
) -> None:
    from ct_lens.core.export import write_csv

    nested = tmp_path / "deep" / "nested"
    path = write_csv(_dataset(crtsh_sample), nested / "dataset.csv")
    assert path.exists()
