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
from dcpstudio.testrunner.cases import (  # noqa: E402
    DEVICE_READ_ONLY_SUITE,
    DEVICE_VALIDATION_SUITE,
    FULL_VALIDATION_SUITE,
    TEST_SUITES,
    TOOL_SELF_TEST_SUITE,
    suite_test_ids,
)


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


def test_config_controls_follow_selected_target():
    app = _app()
    window, app = _window_with_discovery()
    try:
        window._update_config_controls()
        assert window.apply_name_button.isEnabled() is True
        assert window.apply_ip_button.isEnabled() is True
        assert window.apply_reset_button.isEnabled() is True
        # Signal needs a target too, but is not itself a state change.
        assert window.signal_button.isEnabled() is True

        window.selected_device = None
        window._update_config_controls()
        assert window.apply_name_button.isEnabled() is False
        assert window.apply_ip_button.isEnabled() is False
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
        assert len(selected) == len(window._test_row_by_id)
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Checked
            for row in window._test_row_by_id.values()
        )
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Checked
            for row in window._group_row_by_category.values()
        )
    finally:
        window.close()
        app.processEvents()


def test_device_suite_preset_selects_read_checks_and_writes():
    app = _app()
    window = MainWindow()
    try:
        window._apply_suite(DEVICE_VALIDATION_SUITE)
        selected = window._selected_test_ids()
        assert selected == set(suite_test_ids(DEVICE_VALIDATION_SUITE))
        assert {"write.set_name", "write.set_ip", "write.reset"} <= selected
        assert window.suite_preset_combo.currentData() == DEVICE_VALIDATION_SUITE.key
        assert DEVICE_VALIDATION_SUITE.title in window.test_selection_label.text()
        # Every category the suite covers is fully checked; the offline groups are not.
        for category in ("Environment", "Live DCP", "State-changing (optional)"):
            row = window._group_row_by_category[category]
            assert window.test_table.item(row, 0).checkState() == Qt.CheckState.Checked
        for category in ("Offline parser", "Offline transactions", "Offline validation"):
            row = window._group_row_by_category[category]
            assert (
                window.test_table.item(row, 0).checkState() == Qt.CheckState.Unchecked
            )
        # The state-changing declaration is shown, not a modal confirmation.
        assert not window.test_write_declaration_label.isHidden()
        assert "Configuration tab" in window.test_write_declaration_label.text()
    finally:
        window.close()
        app.processEvents()


def test_read_only_presets_never_select_a_state_changing_test():
    app = _app()
    window = MainWindow()
    try:
        for suite in (DEVICE_READ_ONLY_SUITE, TOOL_SELF_TEST_SUITE):
            window._apply_suite(suite)
            selected = window._selected_test_ids()
            assert selected == set(suite.test_ids)
            assert not selected & {"write.set_name", "write.set_ip", "write.reset"}
            assert window.suite_preset_combo.currentData() == suite.key
            assert window.test_write_declaration_label.isHidden()
        # Every suite in the preset control is reachable.
        assert [suite.key for suite in TEST_SUITES] == [
            window.suite_preset_combo.itemData(index)
            for index in range(1, window.suite_preset_combo.count())
        ]
    finally:
        window.close()
        app.processEvents()


def test_full_validation_preset_is_tool_self_test_plus_device_validation():
    app = _app()
    window = MainWindow()
    try:
        window._apply_suite(FULL_VALIDATION_SUITE)
        assert window._selected_test_ids() == set(FULL_VALIDATION_SUITE.test_ids)
        assert set(FULL_VALIDATION_SUITE.test_ids) == set(
            TOOL_SELF_TEST_SUITE.test_ids
        ) | set(DEVICE_VALIDATION_SUITE.test_ids)
    finally:
        window.close()
        app.processEvents()


def test_write_parameters_come_from_the_configuration_and_reset_tabs():
    app = _app()
    window, app = _window_with_discovery()
    try:
        # An invalid name is refused with a pointer to the Configuration tab.
        window.name_edit.setText("bad name")
        _parameters, error = window._write_test_parameters(["write.set_name"])
        assert "Configuration tab" in error
        # Valid values from the tabs become the suite's write parameters.
        window.name_edit.setText("line-77.validated")
        window.ip_edit.setText("192.0.2.77")
        window.mask_edit.setText("255.255.255.0")
        window.gateway_edit.setText("192.0.2.1")
        parameters, error = window._write_test_parameters(
            ["write.set_name", "write.set_ip", "write.reset"]
        )
        assert error == "", error
        assert parameters["write.set_name"]["name"] == "line-77.validated"
        assert parameters["write.set_ip"]["ip_address"] == "192.0.2.77"
        assert parameters["write.reset"] == {
            "reset_mode": window.reset_mode_combo.currentData()
        }
    finally:
        window.close()
        app.processEvents()


def test_device_under_test_selector_lists_discovered_devices():
    app = _app()
    window, app = _window_with_discovery()
    try:
        window._refresh_dut_combo()
        assert window.dut_combo.count() == 4  # placeholder + 3 mock devices
        assert window.dut_combo.currentData() == window.selected_device.mac
        second = window.latest_discovery.devices[1]
        window.dut_combo.setCurrentIndex(window.dut_combo.findData(second.mac))
        app.processEvents()
        assert window._dut_identity().mac == second.mac
        window._apply_suite(DEVICE_VALIDATION_SUITE)
        assert second.mac in window.test_write_declaration_label.text()
    finally:
        window.close()
        app.processEvents()


def test_device_table_selection_drives_the_device_under_test():
    app = _app()
    window, app = _window_with_discovery()
    try:
        devices = window._devices_for_current_interface()
        target = devices[-1]
        window.device_table.selectRow(len(devices) - 1)
        app.processEvents()
        assert window.selected_device.mac == target.mac
        assert window._dut_identity().mac == target.mac
    finally:
        window.close()
        app.processEvents()


def test_group_header_toggles_children_and_child_change_is_partial():
    app = _app()
    window = MainWindow()
    try:
        window._deselect_all_tests()
        group_row = window._group_row_by_category["Live DCP"]
        header = window.test_table.item(group_row, 0)
        header.setCheckState(Qt.CheckState.Checked)
        app.processEvents()
        live_ids = {
            test_id
            for test_id, row in window._test_row_by_id.items()
            if row in window._rows_by_category["Live DCP"]
        }
        assert live_ids <= window._selected_test_ids()
        assert header.checkState() == Qt.CheckState.Checked
        # A manual change drops the preset label back to a custom selection.
        assert window.suite_preset_combo.currentIndex() == 0

        # Unchecking one child turns the header into the partial state.
        child_row = window._rows_by_category["Live DCP"][0]
        window.test_table.item(child_row, 0).setCheckState(Qt.CheckState.Unchecked)
        app.processEvents()
        assert header.checkState() == Qt.CheckState.PartiallyChecked

        header.setCheckState(Qt.CheckState.Unchecked)
        app.processEvents()
        assert not (live_ids & window._selected_test_ids())
    finally:
        window.close()
        app.processEvents()


def _visible_device_rows(window: MainWindow) -> list[object]:
    rows = []
    for row in range(window.device_table.rowCount()):
        if window.device_table.isRowHidden(row):
            continue
        item = window.device_table.item(row, 0)
        rows.append(item.data(Qt.ItemDataRole.UserRole) if item else None)
    return rows


def test_device_search_filter_and_uncommissioned_view():
    app = _app()
    window, app = _window_with_discovery()
    try:
        window.device_search_edit.setText("robot")
        app.processEvents()
        visible = _visible_device_rows(window)
        assert len(visible) == 1
        assert visible[0].name_of_station == "line-01.robot"
        assert "1 of 3 shown" in window.device_count_label.text()

        window.device_search_edit.clear()
        window.uncommissioned_check.setChecked(True)
        app.processEvents()
        visible = _visible_device_rows(window)
        assert len(visible) == 1
        assert not visible[0].name_of_station

        window.uncommissioned_check.setChecked(False)
        app.processEvents()
        assert len(_visible_device_rows(window)) == 3
    finally:
        window.close()
        app.processEvents()


def test_inventory_export_writes_the_discovered_devices(monkeypatch, tmp_path):
    from dcpstudio.gui.tabs import discovery as discovery_module

    app = _app()
    window, app = _window_with_discovery()
    target = tmp_path / "inventory.csv"
    monkeypatch.setattr(
        discovery_module.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *args, **kwargs: (str(target), "CSV files (*.csv)")),
    )
    monkeypatch.setattr(
        discovery_module.QMessageBox,
        "information",
        staticmethod(lambda *args, **kwargs: None),
    )
    try:
        window._export_inventory()
    finally:
        window.close()
        app.processEvents()
    text = target.read_text(encoding="utf-8")
    assert text.splitlines()[0].startswith("mac,name_of_station")
    assert "line-01.conveyor" in text
    assert "line-01.robot" in text
