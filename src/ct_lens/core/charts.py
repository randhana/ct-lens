"""Render the ecosystem analysis to PNG charts (README §3.3, §3.5).

matplotlib is imported lazily and the non-interactive "Agg" backend is selected
so charts render in headless environments (CI, servers) without a display. Like
enrichment, charting is optional — it needs the ``analysis`` extra
(``pip install "ct-lens[analysis]"``) and the rest of the tool works without it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from ct_lens.core.analysis import EcosystemAnalysis

if TYPE_CHECKING:  # pragma: no cover
    pass

#: How many CAs to show individually before grouping the rest as "Other".
_MAX_CA_SLICES = 8


class ChartsUnavailableError(RuntimeError):
    """Raised when charting is requested but matplotlib is not installed."""


def _load_pyplot() -> Any:
    """Import ``matplotlib.pyplot`` with the headless Agg backend."""
    try:
        import matplotlib

        matplotlib.use("Agg")  # headless: no display needed
        import matplotlib.pyplot as plt
    except ImportError as exc:  # pragma: no cover - exercised via patched import
        raise ChartsUnavailableError(
            "charts require the 'analysis' extra; install it with:\n"
            '    pip install "ct-lens[analysis]"'
        ) from exc
    return plt


def chart_ca_shares(analysis: EcosystemAnalysis, path: Path) -> Path:
    """Horizontal bar chart of CA market share."""
    plt = _load_pyplot()
    shares = analysis.ca_shares[:_MAX_CA_SLICES]
    labels = [item.issuer for item in shares]
    values = [item.share * 100 for item in shares]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(labels, values, color="#2b7bba")
    ax.invert_yaxis()  # largest at the top
    ax.set_xlabel("Share of certificates (%)")
    ax.set_title(f"Certificate Authority market share — {analysis.pattern}")
    for i, value in enumerate(values):
        ax.text(value, i, f" {value:.1f}%", va="center")
    fig.tight_layout()
    return _save(fig, path)


def chart_lifetime_distribution(analysis: EcosystemAnalysis, path: Path) -> Path:
    """Bar chart of certificate lifetime buckets."""
    plt = _load_pyplot()
    labels = [label for label, _ in analysis.lifetimes.buckets]
    values = [count for _, count in analysis.lifetimes.buckets]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(labels, values, color="#5aa469")
    ax.set_ylabel("Certificates")
    ax.set_title(f"Certificate lifetime distribution — {analysis.pattern}")
    fig.autofmt_xdate(rotation=20)
    fig.tight_layout()
    return _save(fig, path)


def chart_issuance_over_time(analysis: EcosystemAnalysis, path: Path) -> Path:
    """Line chart of issuance volume per month."""
    plt = _load_pyplot()
    periods = [item.period for item in analysis.issuance_by_month]
    values = [item.count for item in analysis.issuance_by_month]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(periods, values, marker="o", color="#c0587e")
    ax.set_ylabel("Certificates issued")
    ax.set_title(f"Issuance over time — {analysis.pattern}")
    fig.autofmt_xdate(rotation=45)
    fig.tight_layout()
    return _save(fig, path)


def render_all(analysis: EcosystemAnalysis, out_dir: Path) -> list[Path]:
    """Render every chart into ``out_dir`` and return the paths written.

    Charts whose data is empty (e.g. no datable issuance) are skipped.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if analysis.ca_shares:
        written.append(chart_ca_shares(analysis, out_dir / "ca_shares.png"))
    if analysis.lifetimes.count:
        written.append(chart_lifetime_distribution(analysis, out_dir / "lifetimes.png"))
    if analysis.issuance_by_month:
        written.append(chart_issuance_over_time(analysis, out_dir / "issuance_over_time.png"))
    return written


def _save(fig: Any, path: Path) -> Path:
    """Save a figure to ``path`` (creating parents) and close it."""
    import matplotlib.pyplot as plt

    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path
