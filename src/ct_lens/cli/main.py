"""The ``ct-lens`` command-line application.

Built with Typer so that command signatures, help text, and option parsing are
all driven by Python type hints. Output is rendered with Rich for readable
tables in the terminal.

Phase 1 ships a single command, ``scan``, which proves the crt.sh data is
workable by printing a record count, the top issuing CAs, and a few sample
domains. Later phases add ``analyze``, ``report``, and more.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ct_lens import __version__
from ct_lens.core import analysis, collector, export, findings, parser, report
from ct_lens.core.cache import DEFAULT_CACHE_DIR, Cache
from ct_lens.core.collector import CollectionResult
from ct_lens.core.models import Certificate, ScanSummary
from ct_lens.core.sources.crtsh_json import CrtShJsonSource

app = typer.Typer(
    name="ct-lens",
    help="Map the HTTPS certificate landscape of a whole TLD from public CT logs.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    """Print the version and exit (wired to the global ``--version`` flag)."""
    if value:
        console.print(f"ct-lens {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the ct-lens version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """ct-lens — Certificate Transparency landscape analysis (defensive, public-data only)."""


def _render_summary(summary: ScanSummary, result: CollectionResult) -> None:
    """Pretty-print a :class:`ScanSummary` to the terminal."""
    console.print()
    if result.from_cache:
        when = result.fetched_at.astimezone().strftime("%Y-%m-%d %H:%M")
        console.print(f"[dim]served from cache (fetched {when}); use --refresh to re-fetch[/dim]")
    console.print(f"[bold]Pattern:[/bold] {summary.pattern}")
    console.print(f"[bold]CT log records:[/bold] {summary.total_records:,}")
    console.print(f"[bold]Unique domains:[/bold] {summary.unique_domains:,}")

    if summary.top_issuers:
        table = Table(title="Top issuing CAs", title_justify="left", header_style="bold")
        table.add_column("Certificate Authority")
        table.add_column("Records", justify="right")
        table.add_column("Share", justify="right")
        for name, count in summary.top_issuers:
            share = count / summary.total_records if summary.total_records else 0.0
            table.add_row(name, f"{count:,}", f"{share:.1%}")
        console.print()
        console.print(table)

    if summary.sample_domains:
        console.print()
        console.print("[bold]Sample domains:[/bold]")
        for domain in summary.sample_domains:
            console.print(f"  • {domain}")


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="TLD, domain, or crt.sh pattern. Examples: '.lk', 'example.com', '%.lk'.",
    ),
    limit: int | None = typer.Option(
        None,
        "--limit",
        "-n",
        help="Cap the number of records shown (the full set is still cached).",
        min=1,
    ),
    refresh: bool = typer.Option(
        False,
        "--refresh",
        "-r",
        help="Ignore any cached copy and re-fetch from crt.sh.",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Disable the local cache entirely (always fetch, never store).",
    ),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR,
        "--cache-dir",
        help="Directory for cached crt.sh results.",
    ),
    max_age_hours: float = typer.Option(
        24.0,
        "--max-age",
        help="Treat cached data older than this many hours as stale.",
        min=0.0,
    ),
) -> None:
    """Fetch certificates for TARGET from crt.sh and print a quick summary.

    Results are cached on disk, so re-running the same scan is instant and does
    not re-query crt.sh (use --refresh to force a re-fetch).
    """
    cache = None if no_cache else Cache(cache_dir)
    try:
        with (
            CrtShJsonSource() as source,
            console.status(f"Querying crt.sh for {target!r}…", spinner="dots"),
        ):
            result = collector.collect(
                target,
                source,
                cache=cache,
                refresh=refresh,
                max_age=timedelta(hours=max_age_hours),
                limit=limit,
            )
    except ValueError as exc:
        # User error (e.g. empty target) — show a clean message, not a traceback.
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        # Upstream/network failure after retries.
        err_console.print(f"[red]crt.sh error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    summary = collector.summarize_records(result.pattern, result.records)
    _render_summary(summary, result)


@app.command("export")
def export_dataset(
    target: str = typer.Argument(
        ...,
        help="TLD, domain, or crt.sh pattern. Examples: '.lk', 'example.com', '%.lk'.",
    ),
    out_dir: Path = typer.Option(
        Path("output"),
        "--out-dir",
        "-o",
        help="Directory to write the dataset into.",
    ),
    fmt: str = typer.Option(
        "both",
        "--format",
        "-f",
        help="Output format: csv, json, or both.",
        case_sensitive=False,
    ),
    no_dedupe: bool = typer.Option(
        False,
        "--no-dedupe",
        help="Keep pre-certificate/leaf duplicates instead of collapsing them.",
    ),
    enrich: bool = typer.Option(
        False,
        "--enrich",
        help="Download each certificate to add signature algorithm + key type/size "
        "(slower; one crt.sh request per cert; needs the 'analysis' extra).",
    ),
    enrich_limit: int | None = typer.Option(
        None,
        "--enrich-limit",
        help="Enrich at most N certificates (safety cap for large datasets).",
        min=1,
    ),
    refresh: bool = typer.Option(False, "--refresh", "-r", help="Ignore cache and re-fetch."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the local cache."),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", help="Directory for cached crt.sh results."
    ),
    max_age_hours: float = typer.Option(
        24.0, "--max-age", help="Treat cached data older than this many hours as stale.", min=0.0
    ),
) -> None:
    """Fetch, normalise, de-duplicate, and export the certificate dataset.

    Writes a clean CSV/JSON dataset (one row per certificate) with parsed dates,
    certificate lifetime, and a wildcard flag. Pre-certificate duplicates are
    collapsed by default so counts are accurate.
    """
    fmt = fmt.lower()
    if fmt not in {"csv", "json", "both"}:
        err_console.print("[red]Error:[/red] --format must be one of: csv, json, both")
        raise typer.Exit(code=2)

    result, raw_count, certificates = _load_certificates(
        target,
        refresh=refresh,
        no_cache=no_cache,
        cache_dir=cache_dir,
        max_age_hours=max_age_hours,
        dedupe=not no_dedupe,
        enrich=enrich,
        enrich_limit=enrich_limit,
    )

    written = _write_dataset(certificates, out_dir, fmt)

    console.print()
    if result.from_cache:
        console.print("[dim]source: cache[/dim]")
    console.print(f"[bold]Pattern:[/bold] {result.pattern}")
    console.print(f"[bold]Raw records:[/bold] {raw_count:,}")
    console.print(f"[bold]After de-dup:[/bold] {len(certificates):,} certificates")
    if not no_dedupe:
        console.print(
            f"[dim]  ({raw_count - len(certificates):,} pre-cert/leaf duplicates removed)[/dim]"
        )
    for path in written:
        console.print(f"[green]wrote[/green] {path}")


def _enrich(
    certificates: list[Certificate], source: CrtShJsonSource, enrich_limit: int | None
) -> list[Certificate]:
    """Run the optional enrichment step, importing it lazily (needs cryptography)."""
    from ct_lens.core import enrich as enrich_mod

    try:
        return enrich_mod.enrich(certificates, source, limit=enrich_limit)
    except enrich_mod.EnrichmentUnavailableError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def _write_dataset(certificates: list[Certificate], out_dir: Path, fmt: str) -> list[Path]:
    """Write the dataset in the requested format(s); return the paths written."""
    written: list[Path] = []
    if fmt in {"csv", "both"}:
        written.append(export.write_csv(certificates, out_dir / "dataset.csv"))
    if fmt in {"json", "both"}:
        written.append(export.write_json(certificates, out_dir / "dataset.json"))
    return written


def _load_certificates(
    target: str,
    *,
    refresh: bool,
    no_cache: bool,
    cache_dir: Path,
    max_age_hours: float,
    dedupe: bool,
    enrich: bool,
    enrich_limit: int | None,
) -> tuple[CollectionResult, int, list[Certificate]]:
    """Fetch (cache-aware), normalise, optionally enrich — the shared pipeline.

    Returns the collection result, the raw record count (pre-dedupe), and the
    normalised certificates. Converts engine errors into clean CLI exits.
    """
    cache = None if no_cache else Cache(cache_dir)
    try:
        with (
            CrtShJsonSource() as source,
            console.status(f"Querying crt.sh for {target!r}…", spinner="dots"),
        ):
            result = collector.collect(
                target,
                source,
                cache=cache,
                refresh=refresh,
                max_age=timedelta(hours=max_age_hours),
            )
            raw_count = len(result.records)
            certificates = parser.build_dataset(result.records, dedupe=dedupe)
            if enrich:
                with console.status("Enriching certificates (downloading + parsing)…"):
                    certificates = _enrich(certificates, source, enrich_limit)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    return result, raw_count, certificates


@app.command()
def analyze(
    target: str = typer.Argument(
        ...,
        help="TLD, domain, or crt.sh pattern. Examples: '.lk', 'example.com', '%.lk'.",
    ),
    charts: bool = typer.Option(
        False,
        "--charts",
        help="Also render PNG charts (needs the 'analysis' extra).",
    ),
    out_dir: Path = typer.Option(
        Path("output"),
        "--out-dir",
        "-o",
        help="Directory for rendered charts (with --charts).",
    ),
    enrich: bool = typer.Option(
        False,
        "--enrich",
        help="Download certificates to analyse signature algorithm + key sizes.",
    ),
    enrich_limit: int | None = typer.Option(
        None, "--enrich-limit", help="Enrich at most N certificates.", min=1
    ),
    refresh: bool = typer.Option(False, "--refresh", "-r", help="Ignore cache and re-fetch."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the local cache."),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", help="Directory for cached crt.sh results."
    ),
    max_age_hours: float = typer.Option(
        24.0, "--max-age", help="Treat cached data older than this many hours as stale.", min=0.0
    ),
) -> None:
    """Analyse the certificate ecosystem for TARGET (the ".lk report card").

    Reports CA market share, certificate-lifetime distribution, issuance over
    time, and (when enriched) key types and signature algorithms.
    """
    _, _, certificates = _load_certificates(
        target,
        refresh=refresh,
        no_cache=no_cache,
        cache_dir=cache_dir,
        max_age_hours=max_age_hours,
        dedupe=True,
        enrich=enrich,
        enrich_limit=enrich_limit,
    )

    report = analysis.analyze(collector.normalize_pattern(target), certificates)
    _render_analysis(report)

    if charts:
        _render_charts(report, out_dir)


def _render_analysis(report: analysis.EcosystemAnalysis) -> None:
    """Print the ecosystem report card to the terminal."""
    console.print()
    console.print(f"[bold]Pattern:[/bold] {report.pattern}")
    console.print(f"[bold]Certificates:[/bold] {report.total_certificates:,}")
    console.print(f"[bold]Unique domains:[/bold] {report.unique_domains:,}")
    console.print(f"[bold]Wildcard certs:[/bold] {report.wildcard_count:,}")

    if report.ca_shares:
        console.print(
            f"[bold]CA concentration:[/bold] top CA {report.ca_concentration_top1:.1%}, "
            f"top 3 {report.ca_concentration_top3:.1%}"
        )
        table = Table(title="Certificate Authority market share", title_justify="left")
        table.add_column("Certificate Authority")
        table.add_column("Certs", justify="right")
        table.add_column("Share", justify="right")
        for item in report.ca_shares[:10]:
            table.add_row(item.issuer, f"{item.count:,}", f"{item.share:.1%}")
        console.print()
        console.print(table)

    life = report.lifetimes
    if life.count:
        console.print()
        console.print(
            f"[bold]Lifetimes (days):[/bold] min {life.min_days}, median {life.median_days}, "
            f"mean {life.mean_days}, max {life.max_days}"
        )
        life_table = Table(title="Lifetime distribution", title_justify="left")
        life_table.add_column("Bucket")
        life_table.add_column("Certs", justify="right")
        for label, count in life.buckets:
            life_table.add_row(label, f"{count:,}")
        console.print(life_table)

    if report.key_types:
        console.print()
        console.print(
            "[bold]Key types:[/bold] "
            + ", ".join(f"{name} {count:,}" for name, count in report.key_types)
        )
    if report.signature_algorithms:
        console.print(
            "[bold]Signature algorithms:[/bold] "
            + ", ".join(f"{name} {count:,}" for name, count in report.signature_algorithms)
        )


def _render_charts(report: analysis.EcosystemAnalysis, out_dir: Path) -> None:
    """Render charts, importing the charts module lazily (needs matplotlib)."""
    from ct_lens.core import charts

    try:
        written = charts.render_all(report, out_dir)
    except charts.ChartsUnavailableError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print()
    for path in written:
        console.print(f"[green]chart[/green] {path}")


@app.command("report")
def report_command(
    target: str = typer.Argument(
        ...,
        help="TLD, domain, or crt.sh pattern. Examples: '.lk', 'example.com', '%.lk'.",
    ),
    out_dir: Path = typer.Option(
        Path("output"),
        "--out-dir",
        "-o",
        help="Directory for the report, dataset, and charts.",
    ),
    charts: bool = typer.Option(
        True,
        "--charts/--no-charts",
        help="Render charts and embed them in the report (needs the 'analysis' extra).",
    ),
    anonymize: bool = typer.Option(
        True,
        "--anonymize/--no-anonymize",
        help="Anonymise findings in the report (safe default for publishing).",
    ),
    brands_file: Path | None = typer.Option(
        None, "--brands-file", help="Brand/institution labels to protect (one per line)."
    ),
    enrich: bool = typer.Option(
        False, "--enrich", help="Enrich with signature algorithm + key sizes (slower)."
    ),
    enrich_limit: int | None = typer.Option(
        None, "--enrich-limit", help="Enrich at most N certificates.", min=1
    ),
    refresh: bool = typer.Option(False, "--refresh", "-r", help="Ignore cache and re-fetch."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the local cache."),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", help="Directory for cached crt.sh results."
    ),
    max_age_hours: float = typer.Option(
        24.0, "--max-age", help="Treat cached data older than this many hours as stale.", min=0.0
    ),
) -> None:
    """Generate a full Markdown report (+ dataset + charts) for TARGET.

    One command, end to end: fetch, normalise, analyse, find, chart, and write a
    publishable Markdown report that seeds the companion write-up.
    """
    brands = _read_brands(brands_file)

    _, _, certificates = _load_certificates(
        target,
        refresh=refresh,
        no_cache=no_cache,
        cache_dir=cache_dir,
        max_age_hours=max_age_hours,
        dedupe=True,
        enrich=enrich,
        enrich_limit=enrich_limit,
    )

    pattern = collector.normalize_pattern(target)
    report_analysis = analysis.analyze(pattern, certificates)
    results = findings.find_all(certificates, brands=brands, anonymize=anonymize)

    written: list[Path] = []
    written.append(export.write_csv(certificates, out_dir / "dataset.csv"))
    written.append(export.write_json(certificates, out_dir / "dataset.json"))

    chart_files: list[Path] = []
    if charts:
        chart_files = _try_render_charts(report_analysis, out_dir)
        written.extend(chart_files)

    markdown = report.generate_markdown(
        report_analysis, results, chart_files=chart_files, anonymized=anonymize
    )
    written.append(report.write_report(markdown, out_dir / "report.md"))

    console.print()
    console.print(
        f"[bold]Report for {pattern}[/bold] — {len(certificates):,} certificates, "
        f"{len(results):,} findings"
    )
    for path in written:
        console.print(f"[green]wrote[/green] {path}")


def _try_render_charts(report_analysis: analysis.EcosystemAnalysis, out_dir: Path) -> list[Path]:
    """Render charts for the report, degrading gracefully if matplotlib is absent."""
    from ct_lens.core import charts

    try:
        return charts.render_all(report_analysis, out_dir)
    except charts.ChartsUnavailableError:
        err_console.print("[yellow]warning:[/yellow] charts skipped (matplotlib not installed)")
        return []


@app.command("findings")
def findings_command(
    target: str = typer.Argument(
        ...,
        help="TLD, domain, or crt.sh pattern. Examples: '.lk', 'example.com', '%.lk'.",
    ),
    anonymize: bool = typer.Option(
        True,
        "--anonymize/--no-anonymize",
        help="Mask organisation names (safe default for publishing). "
        "Use --no-anonymize only for private disclosure work.",
    ),
    brands_file: Path | None = typer.Option(
        None,
        "--brands-file",
        help="Text file of brand/institution labels to protect (one per line).",
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="Also write findings to this JSON file.",
    ),
    refresh: bool = typer.Option(False, "--refresh", "-r", help="Ignore cache and re-fetch."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the local cache."),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", help="Directory for cached crt.sh results."
    ),
    max_age_hours: float = typer.Option(
        24.0, "--max-age", help="Treat cached data older than this many hours as stale.", min=0.0
    ),
) -> None:
    """Report security findings from public CT data (lookalikes, exposed hosts).

    Findings are anonymised by default so results are safe to publish in
    aggregate. For private responsible-disclosure work, pass --no-anonymize.
    """
    brands = _read_brands(brands_file)

    _, _, certificates = _load_certificates(
        target,
        refresh=refresh,
        no_cache=no_cache,
        cache_dir=cache_dir,
        max_age_hours=max_age_hours,
        dedupe=True,
        enrich=False,
        enrich_limit=None,
    )

    results = findings.find_all(certificates, brands=brands, anonymize=anonymize)
    _render_findings(results, anonymize=anonymize)

    if out is not None:
        _write_findings_json(results, out)
        console.print(f"[green]wrote[/green] {out}")


def _read_brands(brands_file: Path | None) -> list[str] | None:
    """Read a newline-separated brand list, ignoring blanks and comments."""
    if brands_file is None:
        return None
    if not brands_file.exists():
        err_console.print(f"[red]Error:[/red] brands file not found: {brands_file}")
        raise typer.Exit(code=2)
    lines = brands_file.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def _render_findings(results: list[findings.Finding], *, anonymize: bool) -> None:
    """Print findings as a severity-ordered table."""
    console.print()
    if anonymize:
        console.print("[dim]organisation names anonymised (--no-anonymize to reveal)[/dim]")
    if not results:
        console.print("No findings.")
        return

    colours = {"high": "red", "medium": "yellow", "low": "cyan", "info": "white"}
    table = Table(title=f"Security findings ({len(results)})", title_justify="left")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Domain")
    table.add_column("Summary")
    for finding in results:
        colour = colours.get(finding.severity, "white")
        table.add_row(
            f"[{colour}]{finding.severity}[/{colour}]",
            finding.category,
            finding.domain,
            finding.summary,
        )
    console.print(table)


def _write_findings_json(results: list[findings.Finding], out: Path) -> None:
    """Write findings to a JSON file."""
    import json
    from dataclasses import asdict

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([asdict(f) for f in results], indent=2), encoding="utf-8")


@app.command()
def cache(
    clear: bool = typer.Option(
        False,
        "--clear",
        help="Delete all cached results.",
    ),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR,
        "--cache-dir",
        help="Directory the cache lives in.",
    ),
) -> None:
    """Inspect or clear the local crt.sh cache."""
    store = Cache(cache_dir)
    if clear:
        removed = store.clear()
        console.print(f"Cleared {removed} cached result(s) from {store.directory}")
        return
    console.print(f"[bold]Cache directory:[/bold] {store.directory}")
    console.print(f"[bold]Cached results:[/bold] {store.entries()}")


if __name__ == "__main__":  # pragma: no cover
    app()
