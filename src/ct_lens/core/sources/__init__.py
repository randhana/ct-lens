"""Certificate data sources for ct-lens.

Every source implements the :class:`~ct_lens.core.sources.base.CertSource`
interface so the rest of the engine does not care whether the data came from
crt.sh's JSON endpoint, its Postgres mirror, or (later) raw CT logs.
"""

from __future__ import annotations

from ct_lens.core.sources.base import CertSource
from ct_lens.core.sources.crtsh_json import CrtShJsonSource

__all__ = ["CertSource", "CrtShJsonSource"]
