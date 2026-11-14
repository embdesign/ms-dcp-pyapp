"""The application version is declared once, in ``pyproject.toml``.

If this test fails, the package reports a version that no distribution provided:
either ``pyproject.toml`` was changed without reinstalling, or ``__init__.py``
started hard-coding the number again.
"""

from __future__ import annotations

from importlib.metadata import version

import dcpstudio


def test_package_version_comes_from_the_distribution_metadata() -> None:
    assert dcpstudio.__version__ == version("dcp-studio")
    assert dcpstudio.__version__ != "0.0.0+unknown"


def test_package_version_looks_like_a_release_number() -> None:
    major, minor, patch = (dcpstudio.__version__.split(".") + ["", ""])[:3]
    assert major.isdigit() and minor.isdigit() and patch.split("+")[0].isdigit()
