"""ct-lens — map the HTTPS certificate landscape of a whole TLD from public CT logs.

The package is organised so that *all* real logic lives in :mod:`ct_lens.core`.
The command-line interface (:mod:`ct_lens.cli`) and the future web API
(:mod:`ct_lens.api`) are thin presentation layers over that shared engine.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
