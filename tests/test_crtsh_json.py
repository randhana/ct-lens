"""Tests for :mod:`ct_lens.core.sources.crtsh_json`.

All HTTP is mocked with ``respx`` so these tests never reach the real crt.sh.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from ct_lens.core.sources.crtsh_json import CRTSH_URL, CrtShJsonSource


@respx.mock
def test_fetch_parses_records(crtsh_sample: list[dict[str, object]]) -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=crtsh_sample))

    with CrtShJsonSource() as source:
        records = source.fetch("%.lk")

    assert len(records) == 4
    assert records[0].common_name == "example.lk"
    assert records[0].issuer == "Let's Encrypt"


@respx.mock
def test_fetch_respects_limit(crtsh_sample: list[dict[str, object]]) -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=crtsh_sample))

    with CrtShJsonSource() as source:
        records = source.fetch("%.lk", limit=2)

    assert len(records) == 2


@respx.mock
def test_fetch_retries_then_succeeds(crtsh_sample: list[dict[str, object]]) -> None:
    # First call times out, second returns data. With retries=2 and a zero
    # back-off (injected) the fetch should still succeed, instantly.
    route = respx.get(CRTSH_URL)
    route.side_effect = [
        httpx.TimeoutException("boom"),
        httpx.Response(200, json=crtsh_sample),
    ]

    with CrtShJsonSource(retries=2, backoff_s=0.0) as source:
        records = source.fetch("%.lk")

    assert len(records) == 4


@respx.mock
def test_fetch_raises_after_exhausting_retries() -> None:
    respx.get(CRTSH_URL).mock(side_effect=httpx.TimeoutException("always down"))

    with (
        CrtShJsonSource(retries=2, backoff_s=0.0) as source,
        pytest.raises(RuntimeError, match="failed"),
    ):
        source.fetch("%.lk")


@respx.mock
def test_fetch_handles_non_list_payload() -> None:
    # crt.sh very occasionally returns something odd; we return [] not a crash.
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json={"error": "nope"}))

    with CrtShJsonSource() as source:
        assert source.fetch("%.lk") == []
