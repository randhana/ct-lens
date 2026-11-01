"""Tests for :mod:`ct_lens.core.report`."""

from __future__ import annotations

from pathlib import Path

from ct_lens.core.analysis import EcosystemAnalysis, analyze
from ct_lens.core.findings import Finding, find_all
from ct_lens.core.models import CrtShRecord
from ct_lens.core.parser import build_dataset
from ct_lens.core.report import generate_markdown, write_report


def _report_inputs(
    crtsh_sample: list[dict[str, object]],
) -> tuple[EcosystemAnalysis, list[Finding]]:
    certs = build_dataset([CrtShRecord.from_json(r) for r in crtsh_sample])
    return analyze("%.lk", certs), find_all(certs, anonymize=True)


def test_generate_markdown_has_core_sections(crtsh_sample: list[dict[str, object]]) -> None:
    analysis_result, findings = _report_inputs(crtsh_sample)
    md = generate_markdown(analysis_result, findings)

    assert md.startswith("# Certificate landscape")
    for heading in (
        "## Overview",
        "## Who issues HTTPS certificates?",
        "## Certificate hygiene — lifetimes",
        "## Issuance over time",
        "## Security findings",
        "## Methodology & safety",
    ):
        assert heading in md
    # the safety promise must always be present
    assert "No target server was contacted." in md
    assert "Let's Encrypt" in md


def test_generate_markdown_embeds_charts(crtsh_sample: list[dict[str, object]]) -> None:
    analysis_result, findings = _report_inputs(crtsh_sample)
    md = generate_markdown(analysis_result, findings, chart_files=[Path("out/ca_shares.png")])
    assert "![Certificate Authority market share](ca_shares.png)" in md


def test_generate_markdown_flags_non_anonymised(crtsh_sample: list[dict[str, object]]) -> None:
    analysis_result, findings = _report_inputs(crtsh_sample)
    md = generate_markdown(analysis_result, findings, anonymized=False)
    assert "not anonymised" in md


def test_write_report(crtsh_sample: list[dict[str, object]], tmp_path: Path) -> None:
    analysis_result, findings = _report_inputs(crtsh_sample)
    md = generate_markdown(analysis_result, findings)
    path = write_report(md, tmp_path / "report.md")
    assert path.exists()
    assert path.read_text(encoding="utf-8").startswith("# Certificate landscape")
