# Architecture

ct-lens is built around one rule: **all real logic lives in `src/ct_lens/core/`.** The CLI
(`cli/`), the web API (`api/`), and the React app (`web/`) are thin presentation layers over that
shared engine, so a scan produces identical results no matter how it is invoked.

## The pipeline

```
          ┌─────────────────────── core/ ───────────────────────┐
crt.sh ──►│ sources ─► collector ─► parser ─► analysis           │──► CLI (cli/main.py)
(JSON /   │             │   ▲         │        findings           │──► API (api/app.py) ─► web/
 Postgres)│           cache │         │        export / charts    │
          │                 └─────────┘        report             │
          └──────────────────────────────────────────────────────┘
```

## Modules

| Module | Responsibility |
| --- | --- |
| `core/models.py` | `CrtShRecord` (raw crt.sh row), `Certificate` (normalised), `ScanSummary` |
| `core/sources/` | `CertSource` interface; `CrtShJsonSource` (default) and `CrtShPostgresSource` (full dataset) |
| `core/cache.py` | On-disk JSON cache keyed by `(source, pattern)` — fetch once, re-run offline |
| `core/collector.py` | Orchestrates source + cache; pattern normalisation |
| `core/parser.py` | Parse dates/lifetime, **de-duplicate pre-certificate/leaf pairs** |
| `core/analysis.py` | CA market share, lifetime stats, issuance over time, key/sig distributions |
| `core/findings.py` | Lookalike, exposed-host, and suspicious-issuance detectors; anonymisation |
| `core/enrich.py` | Optional: download + parse certs for signature algorithm & key size (`cryptography`) |
| `core/charts.py` | Optional: matplotlib PNG charts (headless, lazy-imported) |
| `core/export.py` | CSV / JSON dataset serialisers (stdlib only) |
| `core/report.py` | Assemble analysis + findings + charts into a Markdown report |

## Key decisions

- **Shared core, thin edges.** No analysis logic is duplicated in the CLI or API.
- **Optional heavy deps.** `cryptography`, `matplotlib`, `psycopg`, and FastAPI are extras, imported
  lazily, so the base install stays small and `scan`/`export` work with no extras.
- **De-duplicate pre-certs.** crt.sh logs a pre-certificate *and* the final certificate with the
  same `(issuer, serial)`. Collapsing them keeps CA-share counts accurate.
- **Cache everything.** crt.sh is shared and flaky; caching makes analysis reproducible and polite.
- **Safety in code, not just docs.** No target is ever contacted, and findings anonymise the
  organisation by default.

## Web API job model

A scan can be slow, so `POST /api/scans` creates a background **job** and returns immediately;
the client polls `GET /api/scans/{id}` until `done`, then fetches `/results` and the dataset
downloads. The job store is process-memory (fine for a single-user tool or demo).
