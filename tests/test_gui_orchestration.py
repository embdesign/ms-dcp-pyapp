"""Targeted orchestration tests for MainWindow helper methods.

These complement the GUI smoke tests: they exercise the decisions MainWindow
makes (target scoping, write config, confirmations, control gating, report
context, test selection) without driving every widget workflow.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from dcpstudio.gui.app import create_application  # noqa: E402
from dcpstudio.gui.main_window import MainWindow  # noqa: E402
from dcpstudio.operations import set_name_spec  # noqa: E402
from dcpstudio.services.discovery import DiscoveryConfig  # noqa: E402
from dcpstudio.services.get import GET_PRESETS, GetConfig  # noqa: E402
from dcpstudio.services.write import identity_text  # noqa: E402


def _app() -> QApplication:
    return QApplication.instance() or create_application(["dcpstudio-orchestration-test"])


@pytest.fixture(autouse=True)
def _dispose_widgets():
    """Close and delete top-level widgets so PySide6 cannot abort at exit."""
    yield
    app = QApplication.instance()
    if app is None:
        return
    for widget in app.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    app.processEvents()


def _window_with_discovery() -> tuple[MainWindow, QApplication]:
    app = _app()
    window = MainWindow()
    window.interface_table.selectRow(0)
    app.processEvents()
    assert window._start_capture() is True
    result = window.discovery_service.discover(DiscoveryConfig(timeout_s=0.5))
    window._on_discovery_finished(result)
    app.processEvents()
    assert window.selected_device is not None
    return window, app


def test_devices_are_scoped_to_the_current_interface():
    app = _app()
    window, app = _window_with_discovery()
    try:
        devices = window._devices_for_current_interface()
        assert len(devices) == 3
        assert all(
            device.interface_id == window.current_interface.id for device in devices
        )
        assert devices == sorted(devices, key=lambda item: item.last_seen, reverse=True)
    finally:
        window.close()
        app.processEvents()


def test_write_config_uses_ui_timeout_vlan_and_pacing():
    app = _app()
    window, app = _window_with_discovery()
    try:
        window.timeout_spin.setValue(4.5)
        window.vlan_spin.setValue(0)
        config = window._current_write_config()
        assert config.timeout_s == 4.5
        assert config.revalidate_timeout_s == 4.5
        assert config.verify_timeout_s == 4.5
        assert config.vlan_id is None
        assert config.min_request_interval_s == window.config.min_request_interval_s
        assert config.verify_after_set is True

        window.vlan_spin.setValue(120)
        assert window._current_write_config().vlan_id == 120
    finally:
        window.close()
        app.processEvents()


def test_confirmation_is_bound_to_interface_and_selected_identity():
    app = _app()
    window, app = _window_with_discovery()
    try:
        target = window.selected_device
        spec = set_name_spec("line-77.gui", permanent=False)
        confirmation = window._confirmation_for(spec, target)
        assert confirmation.interface_id == window.current_interface.id
        assert confirmation.interface_name == window.current_interface.display_name
        assert confirmation.target_mac == target.mac
        assert confirmation.target_identity == identity_text(target)
        assert confirmation.proposed_parameters["BlockQualifier"] == "0x0000"
        assert confirmation.allows_batch is False
        assert confirmation.allows_broadcast is False
    finally:
        window.close()
        app.processEvents()


def test_config_controls_follow_configuration_mode_not_signal():
    app = _app()
    window, app = _window_with_discovery()
    try:
        window._update_config_controls()
        assert window.safety_gate.configuration_mode is False
        assert window.apply_name_button.isEnabled() is False
        assert window.apply_ip_button.isEnabled() is False
        assert window.apply_reset_button.isEnabled() is False
        # Signal is deliberately unguarded but still needs a target.
        assert window.signal_button.isEnabled() is True

        window.safety_gate.enable_configuration_mode(explicit_authorization=True)
        window._update_config_controls()
        assert window.apply_name_button.isEnabled() is True
        assert window.apply_ip_button.isEnabled() is True
        assert window.apply_reset_button.isEnabled() is True
        assert "Disable configuration mode" == window.config_mode_button.text()

        window.safety_gate.disable_configuration_mode()
        window._update_config_controls()
        assert window.apply_name_button.isEnabled() is False
        assert window.apply_reset_button.isEnabled() is False
    finally:
        window.close()
        app.processEvents()


def test_report_context_collects_discovery_and_get_results():
    app = _app()
    window, app = _window_with_discovery()
    try:
        target = window.selected_device
        get_result = window.get_service.get(
            target.mac,
            GetConfig(timeout_s=0.5, selectors=GET_PRESETS["name"].selectors),
        )
        window._on_get_finished(get_result)
        app.processEvents()

        context = window._report_context()
        assert context.interface is not None
        assert context.interface.id == window.current_interface.id
        assert context.discovery is not None
        assert context.discovery.xid == window.latest_discovery.xid
        assert len(context.get_results) == 1
        assert context.get_results[0].target_mac == target.mac
        assert context.config.timeout_s == window.timeout_spin.value()
        assert context.capture_stats["total"] >= 4
        assert context.logs
    finally:
        window.close()
        app.processEvents()


def test_selected_test_ids_reflect_checkbox_state():
    app = _app()
    window = MainWindow()
    try:
        window._deselect_all_tests()
        assert window._selected_test_ids() == set()

        window._select_all_tests()
        selected = window._selected_test_ids()
        assert "parser.fixture_decode" in selected
        assert {"write.set_name", "write.set_ip", "write.reset"} <= selected
        assert len(selected) == window.test_table.rowCount()
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Checked
            for row in range(window.test_table.rowCount())
        )
    finally:
        window.close()
        app.processEvents()
