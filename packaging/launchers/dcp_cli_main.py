"""Frozen entry point for the headless DCP Studio CLI (``dcp-cli``).

The console bundle exists because a windowed executable has no console on
Windows: redirecting stdout from ``dcp-studio.exe`` does not work. Keeping the
CLI in its own bundle also keeps Qt and its plugins out of it.
"""

from __future__ import annotations

from dcpstudio.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
