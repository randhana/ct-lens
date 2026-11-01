"""Tests for the on-disk cache (:mod:`ct_lens.core.cache`)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from ct_lens.core.cache import Cache, _utcnow


def _rows() -> list[dict[str, object]]:
    return [{"id": 1, "issuer_name": "O=Let's Encrypt"}, {"id": 2, "issuer_name": "O=Sectigo"}]


def test_store_then_load_roundtrip(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    cache.store("crtsh-json", "%.lk", _rows())

    entry = cache.load("crtsh-json", "%.lk")
    assert entry is not None
    assert entry.pattern == "%.lk"
    assert entry.records == _rows()


def test_load_miss_returns_none(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    assert cache.load("crtsh-json", "%.nonexistent") is None


def test_stale_entry_is_a_miss(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    # Pretend it was fetched two days ago.
    old = _utcnow() - timedelta(days=2)
    cache.store("crtsh-json", "%.lk", _rows(), now=old)

    # With a 1-day freshness window it should be treated as stale.
    assert cache.load("crtsh-json", "%.lk", max_age=timedelta(days=1)) is None
    # With no max_age it still loads (cache does not expire on its own).
    assert cache.load("crtsh-json", "%.lk") is not None


def test_corrupt_file_is_a_miss(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    path = cache.path_for("crtsh-json", "%.lk")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not valid json", encoding="utf-8")

    assert cache.load("crtsh-json", "%.lk") is None


def test_different_patterns_use_different_files(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    assert cache.path_for("crtsh-json", "%.lk") != cache.path_for("crtsh-json", "%.np")


def test_clear_and_entries(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    cache.store("crtsh-json", "%.lk", _rows())
    cache.store("crtsh-json", "%.np", _rows())
    assert cache.entries() == 2

    removed = cache.clear()
    assert removed == 2
    assert cache.entries() == 0
