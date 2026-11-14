from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from dcpstudio.gui.app import create_application  # noqa: E402
from dcpstudio.gui.main_window import MainWindow  # noqa: E402
from dcpstudio.safety import ConfirmationRequest  # noqa: E402
from dcpstudio.services.discovery import DiscoveryConfig  # noqa: E402
from dcpstudio.services.get import GET_PRESETS, GetConfig  # noqa: E402
from dcpstudio.services.write import (  # noqa: E402
    WriteAuthorization,
    WriteConfig,
    WriteRequest,
    identity_text,
)


def _app() -> QApplication:
    return QApplication.instance() or create_application(["dcpstudio-test"])


def test_window_has_seven_tabs_and_guarded_state_changing_controls():
    app = _app()
    window = MainWindow()
    try:
        assert window.tabs.count() == 7
        assert [window.tabs.tabText(i) for i in range(7)] == [
            "Interfaces & Discovery",
            "Device Details",
            "Configuration",
            "Reset",
            "Test Runner",
            "Packet Capture",
            "Logs & Reports",
        ]
        assert window.apply_name_button.isEnabled() is False
        assert window.apply_ip_button.isEnabled() is False
        assert window.apply_reset_button.isEnabled() is False
        assert window.signal_button.isEnabled() is False
        assert window.cancel_config_write_button.isEnabled() is False
        assert window.cancel_reset_button.isEnabled() is False
        assert window.config_mode_button.isEnabled() is True
        assert window.safety_gate.configuration_mode is False
        assert window.test_table.rowCount() == 20
        # No test is preselected: the operator chooses what to run.
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Unchecked
            for row in range(window.test_table.rowCount())
        )
        assert window.reset_mode_combo.count() == 5
        assert window.reset_mode_combo.itemData(4) == "legacy"
        assert window.current_interface is None
        assert window.discover_button.isEnabled() is False
        window.interface_table.selectRow(0)
        app.processEvents()
        assert window.current_interface is not None
        assert window.current_interface.kind == "mock"
        assert window.discover_button.isEnabled() is True
        app.processEvents()
    finally:
        window.close()
        app.processEvents()


def test_mock_capture_discovery_populates_tables():
    app = _app()
    window = MainWindow()
    try:
        window.interface_table.selectRow(0)
        app.processEvents()
        assert window._start_capture() is True
        assert window.transport is not None
        result = window.discovery_service.discover(DiscoveryConfig(timeout_s=0.5))
        assert len(result.devices) == 3
        window._on_discovery_finished(result)
        app.processEvents()
        assert window.device_table.rowCount() == 3
        assert window.transaction_table.rowCount() >= 4
        assert window.selected_device is not None
        assert window.detail_hex.toPlainText()
        assert window.selected_device.mac in window.config_target_label.text()
        target = window.selected_device
        get_result = window.get_service.get(
            target.mac,
            GetConfig(timeout_s=0.5, selectors=GET_PRESETS["name"].selectors),
        )
        window._on_get_finished(get_result)
        app.processEvents()
        assert get_result.state == "response_received"
        assert get_result.identity is not None
        assert "Get response received" in window.get_result_label.text()
        assert window.latest_get_result is get_result
        # Signal is not a guarded operation: available with configuration mode OFF.
        assert window.safety_gate.configuration_mode is False
        assert window.signal_button.isEnabled() is True
    finally:
        window.close()
        app.processEvents()


def test_guarded_write_updates_device_cache_and_report():
    app = _app()
    window = MainWindow()
    try:
        window.interface_table.selectRow(0)
        app.processEvents()
        assert window._start_capture() is True
        result = window.discovery_service.discover(DiscoveryConfig(timeout_s=0.5))
        window._on_discovery_finished(result)
        app.processEvents()
        target = window.selected_device
        assert target is not None
        window.safety_gate.enable_configuration_mode(explicit_authorization=True)
        window._update_config_controls()
        assert window.apply_name_button.isEnabled() is True
        assert window.signal_button.isEnabled() is True
        confirmation = ConfirmationRequest(
            operation_id="set_name",
            operation_text="Set NameOfStation",
            interface_id=window.current_interface.id,
            target_mac=target.mac,
            target_identity=identity_text(target),
            proposed_parameters={"NameOfStation": "line-77.gui"},
        )
        write_result = window.write_service.execute(
            WriteRequest(
                "set_name",
                target.mac,
                confirmation,
                WriteAuthorization(
                    authorization_confirmed=True,
                    safe_maintenance_confirmed=True,
                ),
                WriteConfig(
                    timeout_s=0.5,
                    revalidate_timeout_s=0.5,
                    verify_timeout_s=0.5,
                    min_request_interval_s=0.05,
                ),
                name="line-77.gui",
                permanent=False,
            )
        )
        window._on_write_finished(write_result)
        app.processEvents()
        assert write_result.state == "acknowledged"
        assert write_result.verification == "verified"
        assert window.latest_write_result is write_result
        assert len(window.write_runs) == 1
        assert "read back" in window.config_result_label.text().lower()
        assert "line-77.gui" in window.config_target_label.text()
        assert len(window._report_context().write_results) == 1
    finally:
        window.close()
        app.processEvents()


def test_select_and_deselect_all_tests_buttons():
    app = _app()
    window = MainWindow()
    try:
        assert window.select_all_tests_button.text() == "Select all tests"
        assert window.deselect_all_tests_button.text() == "Deselect all tests"
        rows = list(range(window.test_table.rowCount()))

        window.deselect_all_tests_button.click()
        app.processEvents()
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Unchecked
            for row in rows
        )

        window.select_all_tests_button.click()
        app.processEvents()
        selectable = [
            row
            for row in rows
            if window.test_table.item(row, 0).flags() & Qt.ItemFlag.ItemIsEnabled
        ]
        assert len(selectable) == window.test_table.rowCount()
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Checked
            for row in selectable
        )
        # The optional guarded tests are selectable too; running them still
        # requires configuration mode, a target and per-operation confirmation.
        guarded = {
            window.test_table.item(row, 1).text()
            for row in selectable
            if window.test_table.item(row, 1).text().startswith("write.")
        }
        assert guarded == {"write.set_name", "write.set_ip", "write.reset"}
    finally:
        window.close()
        app.processEvents()
