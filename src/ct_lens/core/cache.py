"""Local on-disk cache for raw certificate records.

Why this exists
---------------
crt.sh is a free, public, and frequently overloaded service. A broad query like
``%.lk`` can be large and may fail with a ``502`` under load. Caching the raw
result once means:

* every later ``analyze`` / ``report`` run is instant and reproducible,
* we stop hammering crt.sh with identical queries (good manners, see README §9),
* an analysis can be re-run offline, on a plane, in CI, wherever.

Design
------
One JSON file per ``(source, pattern)`` pair, named by a short hash so arbitrary
patterns map to safe filenames. Each file stores a small metadata header plus
the records themselves. Freshness is decided by the caller via ``max_age`` — the
cache does not silently expire anything on its own.

The cache stores plain dictionaries (crt.sh-shaped rows). Converting to and from
:class:`~ct_lens.core.models.CrtShRecord` is the collector's job, which keeps the
cache completely source-agnostic.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

#: Default directory for cached results (relative to the working directory).
DEFAULT_CACHE_DIR: Final = Path(".ct-lens-cache")

#: Default freshness window: data older than this is considered stale.
DEFAULT_MAX_AGE: Final = timedelta(hours=24)

#: Bump if the on-disk layout ever changes, so old files are ignored.
_CACHE_FORMAT_VERSION: Final = 1


def _utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime (easy to test/compare)."""
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class CacheEntry:
    """A cached result: metadata plus the raw records."""

    source: str
    pattern: str
    fetched_at: datetime
    records: list[dict[str, object]]

    def age(self, *, now: datetime | None = None) -> timedelta:
        """How long ago this entry was fetched."""
        return (now or _utcnow()) - self.fetched_at

    def is_fresh(self, max_age: timedelta, *, now: datetime | None = None) -> bool:
        """True if the entry is within ``max_age`` of now."""
        return self.age(now=now) <= max_age


class Cache:
    """A simple, robust JSON file cache keyed by ``(source, pattern)``."""

    def __init__(self, directory: Path | str = DEFAULT_CACHE_DIR) -> None:
        """Create a cache rooted at ``directory`` (created lazily on first write)."""
        self.directory = Path(directory)

    # -- key / path helpers ------------------------------------------------- #

    @staticmethod
    def _key(source: str, pattern: str) -> str:
        """Stable short hash of the (source, pattern) pair for use as a filename."""
        digest = hashlib.sha256(f"{source}|{pattern}".encode()).hexdigest()
        return digest[:16]

    def path_for(self, source: str, pattern: str) -> Path:
        """Return the cache file path for a ``(source, pattern)`` pair."""
        return self.directory / f"{self._key(source, pattern)}.json"

    # -- read --------------------------------------------------------------- #

    def load(
        self,
        source: str,
        pattern: str,
        *,
        max_age: timedelta | None = None,
        now: datetime | None = None,
    ) -> CacheEntry | None:
        """Load a cached entry, or ``None`` on a miss / stale / unreadable file.

        Args:
            source: Source identifier (e.g. ``"crtsh-json"``).
            pattern: The crt.sh query pattern.
            max_age: If given, entries older than this are treated as a miss.
            now: Override "current time" (testing).

        Returns:
            A :class:`CacheEntry`, or ``None`` if there is nothing usable.
        """
        path = self.path_for(source, pattern)
        if not path.exists():
            return None

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt or unreadable cache file should never crash a scan;
            # treat it as a miss and let the caller re-fetch.
            return None

        if not isinstance(payload, dict) or payload.get("version") != _CACHE_FORMAT_VERSION:
            return None

        try:
            entry = CacheEntry(
                source=str(payload["source"]),
                pattern=str(payload["pattern"]),
                fetched_at=datetime.fromisoformat(str(payload["fetched_at"])),
                records=list(payload["records"]),
            )
        except (KeyError, ValueError, TypeError):
            return None

        if max_age is not None and not entry.is_fresh(max_age, now=now):
            return None

        return entry

    # -- write -------------------------------------------------------------- #

    def store(
        self,
        source: str,
        pattern: str,
        records: list[dict[str, object]],
        *,
        now: datetime | None = None,
    ) -> CacheEntry:
        """Persist ``records`` for a ``(source, pattern)`` pair and return the entry."""
        self.directory.mkdir(parents=True, exist_ok=True)
        entry = CacheEntry(
            source=source,
            pattern=pattern,
            fetched_at=now or _utcnow(),
            records=records,
        )
        payload = {
            "version": _CACHE_FORMAT_VERSION,
            "source": entry.source,
            "pattern": entry.pattern,
            "fetched_at": entry.fetched_at.isoformat(),
            "record_count": len(records),
            "records": records,
        }
        path = self.path_for(source, pattern)
        # Write atomically: write to a temp file then replace, so a crash mid-write
        # never leaves a half-written cache file behind.
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(path)
        return entry

    # -- maintenance -------------------------------------------------------- #

    def clear(self) -> int:
        """Delete all cache files. Returns the number of files removed."""
        if not self.directory.exists():
            return 0
        removed = 0
        for path in self.directory.glob("*.json"):
            path.unlink()
            removed += 1
        return removed

    def entries(self) -> int:
        """Count the cache files currently stored."""
        if not self.directory.exists():
            return 0
        return sum(1 for _ in self.directory.glob("*.json"))
