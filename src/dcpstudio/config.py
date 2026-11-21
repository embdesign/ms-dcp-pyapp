"""Configuration and last-used UI state.

Only non-sensitive operational preferences are stored. No credentials, private
keys, or device configuration values are persisted.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from .constants import (
    DEFAULT_MIN_REQUEST_INTERVAL_S,
    DEFAULT_POST_CHECK_WINDOW_S,
    DEFAULT_RESPONSE_DELAY_FACTOR,
)
from .interfaces import MOCK_INTERFACE_ID

CONFIG_SCHEMA_VERSION = 1


def config_directory() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / "DCPStudio"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "DCPStudio"
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "dcp-studio"


def default_report_directory() -> Path:
    return Path.home() / "DCP-Studio-Reports"


@dataclass(slots=True)
class AppConfig:
    schema_version: int = CONFIG_SCHEMA_VERSION
    last_interface_id: str = MOCK_INTERFACE_ID
    timeout_s: float = 3.0
    response_delay_factor: int = DEFAULT_RESPONSE_DELAY_FACTOR
    vlan_id: int | None = None
    min_request_interval_s: float = DEFAULT_MIN_REQUEST_INTERVAL_S
    post_check_window_s: float = DEFAULT_POST_CHECK_WINDOW_S
    max_capture_frames: int = 4000
    report_directory: str = str(default_report_directory())
    show_dcp_only: bool = True
    # Layout preferences (Edit menu); persisted so a small screen keeps its setup.
    show_app_header: bool = True
    show_identify_filters: bool = True
    show_tab_notices: bool = True
    compact_spacing: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppConfig:
        allowed = {f.name for f in fields(cls)}
        clean = {k: v for k, v in data.items() if k in allowed}
        if clean.get("schema_version") != CONFIG_SCHEMA_VERSION:
            clean.pop("schema_version", None)
        return cls(**clean)


def load_config(path: Path | None = None) -> tuple[AppConfig, list[str]]:
    path = path or (config_directory() / "config.json")
    warnings: list[str] = []
    if not path.exists():
        return AppConfig(), warnings
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("configuration root is not an object")
        cfg = AppConfig.from_dict(data)
        return cfg, warnings
    except Exception as exc:
        warnings.append(f"Could not load configuration {path}: {exc}. Defaults will be used.")
        return AppConfig(), warnings


def save_config(config: AppConfig, path: Path | None = None) -> Path:
    path = path or (config_directory() / "config.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(config.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temp.replace(path)
    return path
