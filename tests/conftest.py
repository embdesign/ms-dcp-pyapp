from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Isolate configuration writes from the developer's real profile.
_test_config_root = Path(tempfile.mkdtemp(prefix="dcpstudio-test-config-"))
os.environ["XDG_CONFIG_HOME"] = str(_test_config_root)
os.environ["APPDATA"] = str(_test_config_root)

import pytest  # noqa: E402

from dcpstudio.fixtures import get_fixture  # noqa: E402


@pytest.fixture()
def named_response() -> bytes:
    return get_fixture("identify_response_named")


@pytest.fixture()
def unnamed_response() -> bytes:
    return get_fixture("identify_response_unnamed")
