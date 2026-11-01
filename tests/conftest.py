"""Shared pytest fixtures.

The most important fixture here is ``crtsh_sample``: a recorded crt.sh JSON
response. Tests use it instead of the live service so the suite is fast,
deterministic, and never touches the network (a hard rule — see CONTRIBUTING).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def crtsh_sample() -> list[dict[str, object]]:
    """Return the recorded crt.sh JSON rows for a small ``.lk`` sample."""
    raw = (FIXTURES_DIR / "crtsh_lk_sample.json").read_text(encoding="utf-8")
    data: list[dict[str, object]] = json.loads(raw)
    return data
