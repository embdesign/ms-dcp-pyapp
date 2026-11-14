"""DCP Studio - PROFINET DCP discovery, guarded configuration, and testing.

Phases 1-4 are implemented: read-only discovery/Get plus explicitly enabled,
per-operation-confirmed Set NameOfStation, Set IP parameters and verified reset
variants. See ``docs/protocol-support-matrix.md``.
"""

from __future__ import annotations

__all__ = ["__version__", "APP_NAME", "PHASE"]

APP_NAME = "DCP Studio"
__version__ = "0.1.0"
PHASE = 4
