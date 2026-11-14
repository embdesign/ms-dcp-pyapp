from __future__ import annotations

import json

from dcpstudio.config import AppConfig, load_config, save_config


def test_config_roundtrip(tmp_path):
    path = tmp_path / "config.json"
    config = AppConfig(
        last_interface_id="eth0",
        timeout_s=4.5,
        response_delay_factor=100,
        vlan_id=42,
        show_dcp_only=False,
    )
    save_config(config, path)
    loaded, warnings = load_config(path)
    assert warnings == []
    assert loaded.last_interface_id == "eth0"
    assert loaded.timeout_s == 4.5
    assert loaded.response_delay_factor == 100
    assert loaded.vlan_id == 42
    assert loaded.show_dcp_only is False


def test_config_malformed_uses_defaults(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    loaded, warnings = load_config(path)
    assert loaded.last_interface_id == "mock:demo0"
    assert warnings


def test_config_ignores_unknown_keys(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"schema_version": 1, "unknown": "x"}), encoding="utf-8")
    loaded, warnings = load_config(path)
    assert loaded.timeout_s == 3.0
    assert warnings == []
