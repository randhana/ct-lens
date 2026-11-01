"""Tests for :mod:`ct_lens.core.charts`.

These verify that chart files are actually produced (matplotlib, headless Agg).
"""

from __future__ import annotations

from pathlib import Path

from ct_lens.core.analysis import EcosystemAnalysis, analyze
from ct_lens.core.charts import render_all
from ct_lens.core.models import CrtShRecord
from ct_lens.core.parser import build_dataset


def _report(crtsh_sample: list[dict[str, object]]) -> EcosystemAnalysis:
    certs = build_dataset([CrtShRecord.from_json(r) for r in crtsh_sample])
    return analyze("%.lk", certs)


def test_render_all_writes_png_files(crtsh_sample: list[dict[str, object]], tmp_path: Path) -> None:
    written = render_all(_report(crtsh_sample), tmp_path)

    # CA shares, lifetimes, and issuance-over-time charts should all render.
    assert len(written) == 3
    for path in written:
        assert path.exists()
        assert path.suffix == ".png"
        assert path.stat().st_size > 0


def test_render_all_skips_empty_sections(tmp_path: Path) -> None:
    empty = analyze("%.lk", [])
    assert render_all(empty, tmp_path) == []
