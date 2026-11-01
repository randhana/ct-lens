"""crt.sh JSON certificate source.

crt.sh is a public Certificate Transparency search engine run by Sectigo. Its
JSON endpoint accepts a SQL-``LIKE`` style query and returns one object per CT
log entry::

    https://crt.sh/?q=%25.lk&output=json

``%25`` is a URL-encoded ``%`` (the wildcard). We let ``httpx`` do the encoding
so callers just pass the human pattern ``%.lk``.

Design notes / "code ethics":
    * We send a descriptive ``User-Agent`` so crt.sh operators can see who is
      calling and why. We are guests on a free, public service.
    * crt.sh frequently times out under load, so we use a generous timeout and
      retry a few times with a short back-off instead of hammering it.
    * This source performs **no** connection to any target domain — it only
      reads crt.sh. That is the whole safety premise of the project.
"""

from __future__ import annotations

import time
from typing import Final

import httpx

from ct_lens.core.models import CrtShRecord
from ct_lens.core.sources.base import CertSource

#: Base URL for the crt.sh search endpoint.
CRTSH_URL: Final = "https://crt.sh/"

#: Identifies the tool to crt.sh operators. Update the URL when published.
USER_AGENT: Final = "ct-lens/1.0 (+https://github.com/your-org/ct-lens; CT landscape tool)"

#: crt.sh can be slow; wait generously before giving up on a single request.
DEFAULT_TIMEOUT_S: Final = 60.0

#: How many times to retry a failed/timed-out request before raising.
DEFAULT_RETRIES: Final = 3

#: Seconds to wait between retries (multiplied by the attempt number).
RETRY_BACKOFF_S: Final = 2.0


class CrtShJsonSource(CertSource):
    """Fetch certificate records from the crt.sh JSON endpoint."""

    name = "crtsh-json"

    def __init__(
        self,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        retries: int = DEFAULT_RETRIES,
        backoff_s: float | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        """Create a crt.sh JSON source.

        Args:
            timeout_s: Per-request timeout in seconds.
            retries: Number of retry attempts on timeout / transport errors.
            backoff_s: Base seconds to wait between retries (multiplied by the
                attempt number). Defaults to :data:`RETRY_BACKOFF_S`; tests pass
                ``0.0`` to run instantly.
            client: An optional pre-configured ``httpx.Client`` (mainly used to
                inject a mock client in tests). When omitted, one is created.
        """
        self._timeout_s = timeout_s
        self._retries = max(1, retries)
        self._backoff_s = RETRY_BACKOFF_S if backoff_s is None else backoff_s
        self._owns_client = client is None
        self._client = client or httpx.Client(
            headers={"User-Agent": USER_AGENT},
            timeout=timeout_s,
            follow_redirects=True,
        )

    def fetch(self, pattern: str, *, limit: int | None = None) -> list[CrtShRecord]:
        """Fetch records for ``pattern`` from crt.sh (see :class:`CertSource`)."""
        rows = self._get_json(pattern)
        records = [CrtShRecord.from_json(row) for row in rows]
        if limit is not None:
            records = records[:limit]
        return records

    def _get_json(self, pattern: str) -> list[dict[str, object]]:
        """Perform the HTTP GET with retries and return the parsed JSON list."""
        params = {"q": pattern, "output": "json"}
        last_error: Exception | None = None

        for attempt in range(1, self._retries + 1):
            try:
                response = self._client.get(CRTSH_URL, params=params)
                response.raise_for_status()
                data = response.json()
                # crt.sh returns a JSON array; be defensive about anything else.
                if isinstance(data, list):
                    return [row for row in data if isinstance(row, dict)]
                return []
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as exc:
                last_error = exc
                if attempt < self._retries:
                    time.sleep(self._backoff_s * attempt)

        raise RuntimeError(
            f"crt.sh request for pattern {pattern!r} failed after "
            f"{self._retries} attempts: {last_error}"
        )

    def fetch_certificate_bytes(self, cert_id: int) -> bytes:
        """Download the raw certificate for a crt.sh id (``?d=<id>``).

        crt.sh returns the certificate itself (DER or PEM) at this endpoint.
        Used by the optional enrichment step to read fields — signature
        algorithm, key type/size — that are not present in the JSON index.

        Args:
            cert_id: The crt.sh certificate id.

        Returns:
            The raw certificate bytes (DER or PEM).

        Raises:
            httpx.HTTPError: On a transport or HTTP error (the caller decides
                whether to skip this certificate).
        """
        response = self._client.get(CRTSH_URL, params={"d": str(cert_id)})
        response.raise_for_status()
        return response.content

    def close(self) -> None:
        """Close the underlying HTTP client if this source created it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> CrtShJsonSource:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
