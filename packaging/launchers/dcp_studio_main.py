"""Frozen entry point for the DCP Studio desktop bundle.

PyInstaller analyses this file as a plain script, so it must not rely on package
relative imports. It reuses :func:`dcpstudio.__main__.main`, which keeps the
existing behaviour: arguments launch the CLI, no arguments launch the GUI.
"""

from __future__ import annotations

from dcpstudio.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
