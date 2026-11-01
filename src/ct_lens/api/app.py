"""FastAPI application exposing the ct-lens engine over HTTP (Phase 8).

This is a **thin wrapper** over :mod:`ct_lens.core`: it runs the exact same
collect → parse → analyse → find pipeline the CLI uses, and adds nothing of its
own beyond HTTP plumbing and a small in-memory job store.

Because a crt.sh fetch can be slow, a scan is modelled as a background **job**:

* ``POST /api/scans`` creates a job and starts it in the background,
* ``GET  /api/scans/{id}`` returns its status,
* ``GET  /api/scans/{id}/results`` returns the analysis + findings when done,
* ``GET  /api/scans/{id}/dataset.{csv,json}`` downloads the dataset.

The job store is process-memory only — fine for a single-user tool or a demo;
a real multi-instance deployment would swap in a shared store.

Run it with::

    uvicorn ct_lens.api.app:app --reload
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ct_lens import __version__
from ct_lens.core import analysis, collector, export, findings, parser
from ct_lens.core.cache import Cache
from ct_lens.core.models import Certificate
from ct_lens.core.sources.crtsh_json import CrtShJsonSource

app = FastAPI(
    title="ct-lens API",
    version=__version__,
    summary="Certificate Transparency landscape analysis (defensive, public-data only).",
)

# Allow a separately-served front-end (e.g. the Vite dev server) to call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

#: Shared on-disk cache so the API benefits from the same fetch-once behaviour.
_CACHE = Cache()

#: In-memory job store (process-local). Keyed by job id.
_JOBS: dict[str, Job] = {}


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


class ScanRequest(BaseModel):
    """Body for ``POST /api/scans``."""

    target: str = Field(..., examples=[".lk", "example.com", "%.lk"])
    anonymize: bool = True
    enrich: bool = False
    enrich_limit: int | None = Field(default=None, ge=1)


@dataclass(slots=True)
class Job:
    """A scan job and its lifecycle state."""

    id: str
    target: str
    anonymize: bool
    enrich: bool
    enrich_limit: int | None
    status: str = "pending"  # pending | running | done | error
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: str | None = None
    result: dict[str, Any] | None = None
    certificates: list[Certificate] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        """Status view (without the heavy result payload)."""
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "created_at": self.created_at,
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #


def build_results(
    report: analysis.EcosystemAnalysis, results: list[findings.Finding]
) -> dict[str, Any]:
    """Serialise the analysis + findings into a JSON-friendly dict."""
    payload = asdict(report)
    payload["ca_concentration"] = {
        "top1": report.ca_concentration_top1,
        "top3": report.ca_concentration_top3,
    }
    payload["findings"] = [asdict(finding) for finding in results]
    return payload


# --------------------------------------------------------------------------- #
# Job execution
# --------------------------------------------------------------------------- #


def _run_scan(job_id: str) -> None:
    """Execute a scan job end-to-end, updating its state in the store."""
    job = _JOBS[job_id]
    job.status = "running"
    try:
        with CrtShJsonSource() as source:
            collection = collector.collect(job.target, source, cache=_CACHE)
            certificates = parser.build_dataset(collection.records)
            if job.enrich:
                from ct_lens.core import enrich as enrich_mod

                certificates = enrich_mod.enrich(certificates, source, limit=job.enrich_limit)
        report = analysis.analyze(collection.pattern, certificates)
        found = findings.find_all(certificates, anonymize=job.anonymize)
        job.certificates = certificates
        job.result = build_results(report, found)
        job.status = "done"
    except Exception as exc:
        # Any failure (network, parse, …) becomes the job's error state.
        job.status = "error"
        job.error = str(exc)


def _get_job(job_id: str) -> Job:
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return job


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@app.get("/api/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "version": __version__}


@app.post("/api/scans", status_code=202)
def create_scan(request: ScanRequest, background: BackgroundTasks) -> dict[str, Any]:
    """Create a scan job and start it in the background."""
    if not request.target.strip():
        raise HTTPException(status_code=422, detail="target must not be empty")
    job = Job(
        id=uuid.uuid4().hex,
        target=request.target,
        anonymize=request.anonymize,
        enrich=request.enrich,
        enrich_limit=request.enrich_limit,
    )
    _JOBS[job.id] = job
    background.add_task(_run_scan, job.id)
    return job.public()


@app.get("/api/scans/{job_id}")
def get_scan(job_id: str) -> dict[str, Any]:
    """Return a job's status."""
    return _get_job(job_id).public()


@app.get("/api/scans/{job_id}/results")
def get_results(job_id: str) -> dict[str, Any]:
    """Return a completed job's analysis + findings."""
    job = _get_job(job_id)
    if job.status == "error":
        raise HTTPException(status_code=500, detail=job.error or "scan failed")
    if job.status != "done" or job.result is None:
        raise HTTPException(status_code=409, detail=f"scan not ready (status: {job.status})")
    return job.result


@app.get("/api/scans/{job_id}/dataset.csv")
def get_dataset_csv(job_id: str) -> Response:
    """Download the certificate dataset as CSV."""
    job = _require_done(job_id)
    return Response(content=export.to_csv_text(job.certificates), media_type="text/csv")


@app.get("/api/scans/{job_id}/dataset.json")
def get_dataset_json(job_id: str) -> Response:
    """Download the certificate dataset as JSON."""
    job = _require_done(job_id)
    return Response(content=export.to_json_text(job.certificates), media_type="application/json")


def _require_done(job_id: str) -> Job:
    job = _get_job(job_id)
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"scan not ready (status: {job.status})")
    return job
