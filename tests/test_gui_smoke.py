from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QScrollArea, QTableWidget  # noqa: E402

from dcpstudio.gui.app import create_application  # noqa: E402
from dcpstudio.gui.main_window import MainWindow  # noqa: E402
from dcpstudio.gui.tabs.reset import RESET_TABLE_MIN_HEIGHT  # noqa: E402
from dcpstudio.safety import ConfirmationRequest  # noqa: E402
from dcpstudio.services.discovery import DiscoveryConfig  # noqa: E402
from dcpstudio.services.get import GET_PRESETS, GetConfig  # noqa: E402
from dcpstudio.services.write import (  # noqa: E402
    WriteAuthorization,
    WriteConfig,
    WriteRequest,
    identity_text,
)
from dcpstudio.testrunner.cases import TEST_CASES, TEST_GROUPS  # noqa: E402


def _app() -> QApplication:
    return QApplication.instance() or create_application(["dcpstudio-test"])


def test_window_has_eight_tabs_and_state_changing_controls():
    app = _app()
    window = MainWindow()
    try:
        assert window.tabs.count() == 8
        # Tab text is compared as set: Qt requires '&&' to display a literal
        # '&', because a single '&' introduces a mnemonic.
        assert [window.tabs.tabText(i) for i in range(8)] == [
            "Interfaces && Discovery",
            "Monitor",
            "Device Details",
            "Configuration",
            "Reset",
            "Test Runner",
            "Packet Capture",
            "Logs && Reports",
        ]
        assert window.apply_name_button.isEnabled() is False
        assert window.apply_ip_button.isEnabled() is False
        assert window.apply_reset_button.isEnabled() is False
        assert window.signal_button.isEnabled() is False
        assert window.cancel_config_write_button.isEnabled() is False
        assert window.cancel_reset_button.isEnabled() is False
        # The catalogue is rendered grouped: one header row per category plus
        # one row per test, and every test starts deselected.
        assert window.test_table.columnCount() == 5
        assert len(window._test_row_by_id) == len(TEST_CASES) == 22
        assert len(window._group_row_by_category) == len(TEST_GROUPS) == 6
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Unchecked
            for row in window._test_row_by_id.values()
        )
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Unchecked
            for row in window._group_row_by_category.values()
        )
        assert window.run_suite_button.text() == "Run device validation suite"
        assert window.suite_preset_combo.currentData() is None
        assert window.suite_preset_combo.count() == 5
        assert window.dut_combo.count() == 1
        assert window.test_write_declaration_label.isHidden()
        assert "0 of" in window.test_selection_label.text()
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


def test_configuration_tab_scrolls_instead_of_squeezing_fields():
    """The Configuration page keeps its fields at full height.

    At the window minimum size the form is taller than the tab pane. Without a
    scroll area the layout compressed the line edits below their text height
    (the IP and subnet fields reached height 0), so the page is now a
    scrollable form and the pane scrolls instead.
    """
    app = _app()
    window = MainWindow()
    try:
        window.show()
        window.resize(1100, 760)
        window.tabs.setCurrentWidget(window.configuration_tab)
        app.processEvents()
        page = window.configuration_tab
        assert isinstance(page, QScrollArea)
        assert page.widgetResizable() is True
        assert page.verticalScrollBar().isVisible() is True
        for edit in (
            window.name_edit,
            window.ip_edit,
            window.mask_edit,
            window.gateway_edit,
        ):
            assert edit.height() >= edit.minimumSizeHint().height()
    finally:
        window.close()
        app.processEvents()


def test_reset_tab_scrolls_and_keeps_its_mode_table_readable():
    """The Reset page scrolls instead of squeezing its reset-mode table."""
    app = _app()
    window = MainWindow()
    try:
        window.show()
        window.resize(1100, 760)
        window.tabs.setCurrentWidget(window.reset_tab)
        app.processEvents()
        page = window.reset_tab
        assert isinstance(page, QScrollArea)
        assert page.widgetResizable() is True
        table = page.widget().findChild(QTableWidget)
        assert table is not None
        assert table.height() >= RESET_TABLE_MIN_HEIGHT
        assert page.verticalScrollBar().isVisible() is True
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
        # Signal is not a state change: available whenever a target is selected.
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
        rows = list(window._test_row_by_id.values())
        group_rows = list(window._group_row_by_category.values())

        window.deselect_all_tests_button.click()
        app.processEvents()
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Unchecked
            for row in rows
        )
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Unchecked
            for row in group_rows
        )

        window.select_all_tests_button.click()
        app.processEvents()
        selectable = [
            row
            for row in rows
            if window.test_table.item(row, 0).flags() & Qt.ItemFlag.ItemIsEnabled
        ]
        assert len(selectable) == len(TEST_CASES)
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Checked
            for row in selectable
        )
        # Each category header follows its children.
        assert all(
            window.test_table.item(row, 0).checkState() == Qt.CheckState.Checked
            for row in group_rows
        )
        # The optional state-changing tests are selectable too; running them
        # still requires a declared device under test.
        guarded = {
            window.test_table.item(row, 1).text()
            for row in selectable
            if window.test_table.item(row, 1).text().startswith("write.")
        }
        assert guarded == {"write.set_name", "write.set_ip", "write.reset"}
    finally:
        window.close()
        app.processEvents()


def test_hex_dump_panels_use_a_fixed_width_font():
    """Hex dumps must stay column-aligned despite the window style sheet.

    ``MainWindow``'s style sheet assigns a proportional ``font-family`` to
    every ``QWidget``, which overrides ``QWidget.setFont``. A proportional
    face renders ``i`` far narrower than ``M``.
    """
    app = _app()
    window = MainWindow()
    try:
        window.show()
        app.processEvents()
        for panel in (window.packet_detail, window.detail_hex):
            metrics = panel.fontMetrics()
            assert metrics.horizontalAdvance("i" * 8) == metrics.horizontalAdvance(
                "M" * 8
            ), f"hex dump resolved to {panel.font().family()!r}"
    finally:
        window.close()
        window.deleteLater()
        app.processEvents()
