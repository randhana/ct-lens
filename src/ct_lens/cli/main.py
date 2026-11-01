"""The ``ct-lens`` command-line application.

Built with Typer so that command signatures, help text, and option parsing are
all driven by Python type hints. Output is rendered with Rich for readable
tables in the terminal.

Phase 1 ships a single command, ``scan``, which proves the crt.sh data is
workable by printing a record count, the top issuing CAs, and a few sample
domains. Later phases add ``analyze``, ``report``, and more.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from ct_lens import __version__
from ct_lens.core import collector
from ct_lens.core.models import ScanSummary
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


def _render_summary(summary: ScanSummary) -> None:
    """Pretty-print a :class:`ScanSummary` to the terminal."""
    console.print()
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
        help="Cap the number of records fetched (useful for a quick look).",
        min=1,
    ),
) -> None:
    """Fetch certificates for TARGET from crt.sh and print a quick summary.

    This is the Phase 1 spike: it confirms the data is reachable and sane before
    the heavier collect/parse/analyse pipeline runs.
    """
    try:
        with (
            CrtShJsonSource() as source,
            console.status(f"Querying crt.sh for {target!r}…", spinner="dots"),
        ):
            summary = collector.scan(target, source, limit=limit)
    except ValueError as exc:
        # User error (e.g. empty target) — show a clean message, not a traceback.
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        # Upstream/network failure after retries.
        err_console.print(f"[red]crt.sh error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _render_summary(summary)


if __name__ == "__main__":  # pragma: no cover
    app()
