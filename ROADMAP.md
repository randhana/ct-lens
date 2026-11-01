# ct-lens — Roadmap

ct-lens is built in small, independently shippable phases. **Part A** delivers the
command-line tool; **Part B** adds a web UI on top of the same engine. All real logic lives in
`src/ct_lens/core/`, so the CLI and the (future) web API are thin wrappers over one shared core.

**Status legend:** ✅ done · 🚧 in progress · ⬜ planned

| # | Phase | What it adds | Status |
|---|-------|--------------|--------|
| **Part A — Console (CLI)** | | | |
| 0 | Scaffold & tooling | src-layout package, `pyproject.toml`, MIT license, ruff + mypy(strict) + pytest, GitHub Actions CI, pre-commit | ✅ |
| 1 | Spike | crt.sh JSON source (polite UA, timeout, retry/back-off); `ct-lens scan <target>` → record count + top CAs + sample domains | ✅ |
| 2 | Collector + cache | On-disk JSON cache (fetch once, re-run offline/instant); `--refresh` / `--no-cache` / `--cache-dir` / `--max-age`; `ct-lens cache` | ✅ |
| 3 | Parser → dataset | Normalised `Certificate` model (parsed dates, lifetime, wildcard flag); **pre-certificate de-duplication**; optional key/signature enrichment; CSV + JSON export (`ct-lens export`) | ✅ |
| 4 | Ecosystem analysis + charts | CA market share, certificate-lifetime trends, signature-algorithm / key-size adoption, issuance volume over time; matplotlib charts (`ct-lens analyze`) | ✅ |
| 5 | Security findings | Lookalike / typosquat detection, exposed internal/staging hostname catalogue, suspicious issuance — anonymised by default | ✅ |
| 6 | Report generation | Assemble dataset + charts + findings into a Markdown report (`ct-lens report <target>`) | ✅ |
| 7 | CLI polish + full dataset | crt.sh **Postgres** source for the complete set, `--source` switch, confirm TLD-agnostic, finalise subcommands | ✅ |
| **Part B — Web UI** | | | |
| 8 | API layer | FastAPI wrapping the core: `POST /api/scans`, job status, results JSON, dataset export — thin wrapper, no duplicated logic | ✅ |
| 9 | React dashboard | Vite + React + TypeScript: run a scan, interactive charts (Recharts), findings tables, export | ✅ |
| 10 | Open-source polish | Screenshots/GIF, usage + architecture docs, example dataset, hosted demo, `v1.0.0` release | ⬜ |

## Where to look

- **This file** — the high-level map and current status.
- **Git history** (`git log --oneline`) — each phase is a self-contained commit with a detailed message.
- **`README.md`** — the project's purpose, data sources, safety rules, and scope.
- **`CONTRIBUTING.md`** — the two non-negotiable safety rules (no target contact, no name-and-shame).

## Safety, by design (README §5–§6)

ct-lens only ever reads public Certificate Transparency logs — it **never contacts a target
server**, and published output is **aggregate / anonymised**. These rules are enforced in code,
not just documented.
