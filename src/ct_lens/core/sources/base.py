"""Abstract base class that all certificate sources implement.

Keeping a single interface means the collector, parser, and analysis code are
written once and work regardless of where the certificate records come from
(crt.sh JSON today; crt.sh Postgres and raw CT logs later).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ct_lens.core.models import CrtShRecord


class CertSource(ABC):
    """Interface for anything that can supply certificate records for a pattern."""

    #: Short, stable identifier used in cache keys and logs (e.g. ``"crtsh-json"``).
    name: str = "unknown"

    @abstractmethod
    def fetch(self, pattern: str, *, limit: int | None = None) -> list[CrtShRecord]:
        """Return certificate records matching ``pattern``.

        Args:
            pattern: A crt.sh-style query pattern, e.g. ``%.lk`` for every
                ``.lk`` domain, or ``%.example.com`` for one organisation.
            limit: Optional cap on the number of records returned. ``None``
                means "everything the source has" (used for full scans).

        Returns:
            A list of :class:`~ct_lens.core.models.CrtShRecord`.
        """
        raise NotImplementedError

    def close(self) -> None:  # noqa: B027 - intentional no-op default, not abstract
        """Release any resources held by the source (no-op by default)."""

    def __enter__(self) -> CertSource:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
