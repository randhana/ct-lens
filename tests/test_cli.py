"""End-to-end tests for the Typer CLI (:mod:`ct_lens.cli.main`).

Uses Typer's ``CliRunner`` and mocks crt.sh with ``respx`` — no network.
"""

from __future__ import annotations

from pathlib import Path

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

    result = runner.invoke(app, ["scan", ".lk", "--no-cache"])

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

    result = runner.invoke(app, ["scan", ".lk", "--no-cache"])

    assert result.exit_code == 1


@respx.mock
def test_scan_uses_cache_on_second_run(
    crtsh_sample: list[dict[str, object]], tmp_path: Path
) -> None:
    route = respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=crtsh_sample))
    cache_dir = str(tmp_path)

    first = runner.invoke(app, ["scan", ".lk", "--cache-dir", cache_dir])
    second = runner.invoke(app, ["scan", ".lk", "--cache-dir", cache_dir])

    assert first.exit_code == 0
    assert second.exit_code == 0
    # Only the first run hit crt.sh; the second was served from cache.
    assert route.call_count == 1
    assert "served from cache" in second.stdout


def test_cache_command_reports_and_clears(tmp_path: Path) -> None:
    cache_dir = str(tmp_path)
    info = runner.invoke(app, ["cache", "--cache-dir", cache_dir])
    assert info.exit_code == 0
    assert "Cached results:" in info.stdout

    cleared = runner.invoke(app, ["cache", "--clear", "--cache-dir", cache_dir])
    assert cleared.exit_code == 0
    assert "Cleared" in cleared.stdout
