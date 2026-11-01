# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-01

First complete release — the full CLI plus a web dashboard, built on one shared engine.

### Added

- **Collector & cache** — crt.sh JSON source with polite User-Agent, timeout, and retry/back-off;
  on-disk cache so analyses are reproducible and offline (`scan`, `cache`).
- **Dataset** — normalised `Certificate` model with parsed dates, lifetime, and wildcard flag;
  pre-certificate/leaf de-duplication; CSV + JSON export (`export`).
- **Ecosystem analysis** — CA market share & concentration, certificate-lifetime distribution,
  issuance over time, key-type / signature-algorithm adoption; matplotlib charts (`analyze`).
- **Security findings** — lookalike/typosquat, exposed internal/staging hostnames, and suspicious
  issuance; anonymised by default (`findings`).
- **Reports** — one-command Markdown report bundling dataset, charts, and findings (`report`).
- **Full dataset** — optional crt.sh PostgreSQL source via `--source postgres`.
- **Web** — FastAPI backend (`ct_lens.api.app`) exposing the engine as background scan jobs, and a
  Vite + React + TypeScript dashboard (`web/`) with interactive Recharts charts and exports.

### Quality

- Strict `mypy`, `ruff` lint + format, and a fast, network-free `pytest` suite (74 tests) run in
  GitHub Actions CI on Python 3.10–3.12.
