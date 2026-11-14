"""DCP Studio - PROFINET DCP discovery, guarded configuration, and testing.

Phases 1-4 are implemented: read-only discovery/Get plus explicitly enabled,
per-operation-confirmed Set NameOfStation, Set IP parameters and verified reset
variants. See ``docs/protocol-support-matrix.md``.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

__all__ = ["__version__", "APP_NAME", "PHASE"]

APP_NAME = "DCP Studio"
PHASE = 4

# `pyproject.toml` is the single source of truth for the version; never repeat
# the number here. The fallback only applies to an interpreter that imported
# this package from a source tree that was never installed.
try:
    __version__ = _distribution_version("dcp-studio")
except PackageNotFoundError:  # pragma: no cover - uninstalled source tree
    __version__ = "0.0.0+unknown"
