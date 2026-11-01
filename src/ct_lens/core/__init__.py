"""Core engine for ct-lens.

This subpackage holds every piece of real logic: data models, certificate
sources, the collector, parsing, analysis, findings, and report assembly.
Both the CLI and the web API import from here and must not re-implement any of
it.
"""

from __future__ import annotations
