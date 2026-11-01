"""End-to-end tests for the Typer CLI (:mod:`ct_lens.cli.main`).

Uses Typer's ``CliRunner`` and mocks crt.sh with ``respx`` — no network.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from typer.testing import CliRunner

from ct_lens import __version__
from ct_lens.cli.main import app
from ct_lens.core.sources.crtsh_json import CRTSH_URL

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


@respx.mock
def test_scan_command_renders_summary(crtsh_sample: list[dict[str, object]]) -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=crtsh_sample))

    result = runner.invoke(app, ["scan", ".lk"])

    assert result.exit_code == 0
    assert "%.lk" in result.stdout
    assert "Let's Encrypt" in result.stdout
    assert "Sample domains" in result.stdout


@respx.mock
def test_scan_command_reports_upstream_error(monkeypatch: pytest.MonkeyPatch) -> None:
    respx.get(CRTSH_URL).mock(side_effect=httpx.TimeoutException("down"))

    # The CLI builds the source internally, so zero the module-level back-off
    # default (read at construction time) to keep this test fast.
    monkeypatch.setattr("ct_lens.core.sources.crtsh_json.RETRY_BACKOFF_S", 0.0)

    result = runner.invoke(app, ["scan", ".lk"])

    assert result.exit_code == 1
