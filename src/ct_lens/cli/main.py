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
from ct_lens.core import collector, export, parser
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
            certificates = parser.build_dataset(result.records, dedupe=not no_dedupe)

            if enrich:
                with console.status("Enriching certificates (downloading + parsing)…"):
                    certificates = _enrich(certificates, source, enrich_limit)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

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
