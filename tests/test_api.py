"""Tests for the FastAPI layer (:mod:`ct_lens.api.app`).

crt.sh is mocked with respx; the cache is pointed at a temp dir so tests stay
isolated. With Starlette's TestClient, background tasks run before the POST
response returns, so a job is already finished when we read it back.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from ct_lens.api import app as api_module
from ct_lens.core.cache import Cache
from ct_lens.core.sources.crtsh_json import CRTSH_URL

client = TestClient(api_module.app)


@pytest.fixture(autouse=True)
def _temp_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate the API's shared cache per test."""
    monkeypatch.setattr(api_module, "_CACHE", Cache(tmp_path))
    api_module._JOBS.clear()


def test_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@respx.mock
def test_scan_lifecycle(crtsh_sample: list[dict[str, object]]) -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=crtsh_sample))

    created = client.post("/api/scans", json={"target": ".lk"})
    assert created.status_code == 202
    job_id = created.json()["id"]

    # TestClient ran the background task, so the job is already done.
    status = client.get(f"/api/scans/{job_id}")
    assert status.status_code == 200
    assert status.json()["status"] == "done"

    results = client.get(f"/api/scans/{job_id}/results")
    assert results.status_code == 200
    body = results.json()
    assert body["total_certificates"] == 4
    assert body["ca_shares"][0]["issuer"] == "Let's Encrypt"
    assert body["ca_concentration"]["top1"] == 0.5
    assert "findings" in body
    # the full domain/subdomain list is included and sorted
    assert "example.lk" in body["domains"]
    assert "www.example.lk" in body["domains"]
    assert body["domains"] == sorted(body["domains"])


@respx.mock
def test_dataset_downloads(crtsh_sample: list[dict[str, object]]) -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=crtsh_sample))
    job_id = client.post("/api/scans", json={"target": ".lk"}).json()["id"]

    csv_response = client.get(f"/api/scans/{job_id}/dataset.csv")
    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert "cert_id" in csv_response.text

    json_response = client.get(f"/api/scans/{job_id}/dataset.json")
    assert json_response.status_code == 200
    assert isinstance(json_response.json(), list)


def test_unknown_job_is_404() -> None:
    assert client.get("/api/scans/does-not-exist").status_code == 404


@respx.mock
def test_scan_error_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    respx.get(CRTSH_URL).mock(side_effect=httpx.ConnectError("down"))
    # zero the retry back-off so the (failing) fetch returns quickly
    monkeypatch.setattr("ct_lens.core.sources.crtsh_json.RETRY_BACKOFF_S", 0.0)

    job_id = client.post("/api/scans", json={"target": ".lk"}).json()["id"]

    status = client.get(f"/api/scans/{job_id}")
    assert status.json()["status"] == "error"
    assert client.get(f"/api/scans/{job_id}/results").status_code == 500
