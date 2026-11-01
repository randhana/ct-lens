# ct-lens

> An open-source tool that analyses **Certificate Transparency (CT)** logs to map the
> HTTPS certificate landscape of a whole top-level domain — starting with `.lk`
> (Sri Lanka) — using only public data, without ever connecting to a target server.

**Working name:** `ct-lens` (a lens onto Certificate Transparency). Rename freely.

**Status:** project idea / specification. No code yet. This document is the plan to build from.

---

## 1. Why this exists

Every valid HTTPS certificate on the internet is recorded in public, append-only
**Certificate Transparency logs**. Certificate Authorities (CAs) are required to publish
an entry for every certificate they issue, and browsers reject certificates that are not
logged. That means there is a complete, public, searchable record of essentially every
certificate ever issued — including every `.lk` domain.

`ct-lens` reads that public record and answers questions nobody has published answers to
about a country's (or any TLD's) certificate ecosystem. It is **defensive / threat-intel
work**: the same technique security teams use to watch for certificates issued against
their own brand.

### Design thesis — what makes this safe and worth doing

- **Zero target contact.** The tool never connects to a bank, a government site, or any
  target server. It only reads CT logs that CAs are required to publish. (This is the
  whole point: no active scanning, no probing, no unauthorized-access risk.)
- **100% public data.** Everything comes from CT logs / crt.sh. Nothing private is accessed.
- **Original.** "The certificate landscape of `.lk`, 2026" has not been written. The output
  is a dataset we assemble and questions we answer, not a summary of known material.
- **Reusable.** Default target is `.lk`, but the tool takes any TLD (or domain pattern),
  so others can rerun it for their own country or organisation.

---

## 2. Data sources

All public. No credentials against any target.

| Source | What it gives | How |
| --- | --- | --- |
| **crt.sh web/JSON** | Searchable CT index. Wildcard query returns every cert for a pattern. | `https://crt.sh/?q=%25.lk&output=json` |
| **crt.sh PostgreSQL** | The same data as a public SQL database — millions of rows, richer queries. | Public read-only Postgres endpoint |
| **Raw CT logs (optional, later)** | Lower-level log entries direct from Google/Cloudflare/etc. logs. | CT log HTTP APIs |

Primary source for v1: **crt.sh** (JSON for a quick start, Postgres for the full dataset).

---

## 3. Core features (scope for the tool)

### 3.1 Collect
- Fetch all certificates for a given TLD or domain pattern (default: `%.lk`).
- Handle pagination / large result sets and rate limits politely.
- Cache raw results locally so analysis is repeatable without re-fetching.

### 3.2 Parse & build the dataset
For each certificate, extract and normalise:
- Domain name(s) / SANs
- Issuing CA
- Not-before / not-after dates → **certificate lifetime**
- Signature algorithm
- Key type and size
- Entry timestamp

Output a clean, queryable dataset (CSV + JSON).

### 3.3 Ecosystem analysis (the "report card", aggregate only)
- **Who controls `.lk` HTTPS?** Share of certificates by issuing CA (Let's Encrypt vs.
  commercial CAs vs. local CA). Is the country dependent on one or two issuers?
- **Hygiene over time:** certificate lifetimes trend (as the industry moved to 90-day and
  shorter certs), signature-algorithm and key-size adoption, any lingering weak/deprecated
  practices.
- **Volume & growth:** issuance over time.

### 3.4 Security findings (from public data only)
- **Lookalike / typosquat detection:** certificates for domains that imitate a known
  brand or institution (e.g. `bankofceyl0n.lk`). A lookalike cert in the logs is often the
  first visible sign of a phishing operation being set up.
- **Exposed internal / staging hostnames:** organisations frequently leak hostnames like
  `vpn-test.internal.example.lk` or `admin-staging.example.lk` into certificates without
  realising CT makes them public permanently. Catalogue these (anonymised where sensitive).
- **Suspicious issuance:** a cert for a sensitive domain issued by a CA that org would not
  normally use.

### 3.5 Output
- Machine-readable dataset (CSV / JSON).
- Charts for the report: issuance by CA, lifetimes over time, algorithm adoption.
- A summary (Markdown) that can seed the companion blog post.

---

## 4. Deliverables

1. **The open-source tool** (this repo) — rerunnable for any TLD, documented, on GitHub.
2. **A companion write-up:** "The certificate landscape of `.lk`, 2026" — charts + the
   original findings. Published on the blog.

---

## 5. Responsible disclosure & publishing rules

These are part of the project, not an afterthought.

- **Publish ecosystem stats in aggregate / anonymised.** The report never names an
  organisation as "insecure." It reports on the population (e.g. "X% still use weak
  algorithm Y"), which removes any defamation / reputational surface.
- **If a specific finding is sensitive** (a live phishing lookalike, an exposed internal
  host that reveals an attack surface): report it **privately** to the affected
  organisation and to **Sri Lanka CERT|CC** and/or **TechCERT** first. Publish only after
  it is resolved, or publish only in anonymised aggregate.
- Going through the official CERT channel is both safer and a stronger professional signal
  than unilateral publication.

---

## 6. Explicitly out of scope

To keep the project clean, safe, and focused, `ct-lens` does **not**:
- Connect to, scan, or probe any target server (no live TLS handshakes, no port scanning,
  no vulnerability probing).
- Name-and-shame specific institutions in the public report.
- Attempt any exploitation of anything it finds.

If a later version adds *passive* live checks (e.g. observing a server's advertised TLS
config the way SSL Labs does), that is a separate, clearly-scoped decision — not part of v1.

---

## 7. Suggested tech stack (to confirm when building)

Flexible; chosen to match existing skills.

- **Language:** Python (fits the data-pipeline work; same toolkit as the fd-rates pipeline).
- **Fetch:** `requests` / `httpx` for crt.sh JSON; `psycopg`/`psycopg2` for the crt.sh Postgres.
- **Parse certs:** `cryptography` library.
- **Analyse:** `pandas`.
- **Charts:** `matplotlib` (or export data and chart in the blog).
- **Packaging:** a small CLI (`ct-lens <tld>`), reproducible with a `requirements.txt` /
  `pyproject.toml`.

Final choices to be made at build time.

---

## 8. Rough build phases

1. **Spike:** query crt.sh JSON for `%.lk`, pull a sample, print count + top issuing CAs +
   sample domains. (Confirms the data is workable before building further.)
2. **Collector:** full, cached, paginated fetch of the `.lk` dataset (JSON first, Postgres
   for the complete set).
3. **Parser → dataset:** normalise into CSV/JSON with the fields in §3.2.
4. **Ecosystem analysis + charts** (§3.3).
5. **Security findings** (§3.4): lookalike detection, exposed-hostname catalogue.
6. **Report generation** (§3.5) + write the companion blog post.
7. **Polish for open source:** CLI, docs, make it TLD-agnostic, publish to GitHub.

---

## 9. Notes

- Legality: reading CT logs is reading data CAs are required to publish; this is what
  crt.sh, SSL Labs, Hardenize and others do publicly. The project stays on the safe side by
  never contacting targets and by following the disclosure rules in §5.
- Keep the tool generic enough that the `.lk` run is just the first of many possible runs.
