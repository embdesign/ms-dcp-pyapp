"""Test Runner tab construction and orchestration."""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...constants import SUPPORTED_RESET_MODES
from ...html_render import esc
from ...model import DeviceIdentity, TestResult
from ...services.write import WriteAuthorization
from ...testrunner.cases import (
    DEVICE_VALIDATION_SUITE,
    TEST_CASES,
    TEST_SUITES,
    TestSuite,
    grouped_cases,
    suite_test_ids,
)
from ...testrunner.runner import TestRunner
from ...validation import validate_ip_suite, validate_station_name
from ..workers import TestWorker
from .common import banner
from .common import table_item as _item


class TestRunnerTabMixin:
    """Test catalogue grouped by category, with read/write validation suites."""

    # One role on every checkable cell: ("group", category) or ("test", test_id).
    _TEST_ROLE = Qt.ItemDataRole.UserRole

    def _build_test_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(
            banner(
                "Functional and interoperability checks, not official PROFINET "
                "conformance certification. Tests are grouped by category. The device "
                "validation suites also send one Set NameOfStation, one Set IP and one "
                "ResetToFactorySettings to the device under test, because a device is "
                "not validated until those have been attempted; each frame is sent "
                "exactly once, revalidated and read back, with no retry and no "
                "rollback. That needs configuration mode and a declared device under "
                "test. The read-only suites transmit Identify/Get frames only.",
                "Warning",
            )
        )
        self._suppress_test_item_changed = False
        self._last_suite: TestSuite | None = None

        run_controls = QHBoxLayout()
        self.run_suite_button = QPushButton("Run device validation suite")
        self.run_suite_button.setObjectName("primary")
        self.run_suite_button.setToolTip(DEVICE_VALIDATION_SUITE.description)
        self.run_suite_button.clicked.connect(self._run_device_suite)
        self.run_tests_button = QPushButton("Run selected tests")
        self.run_tests_button.clicked.connect(self._run_tests)
        self.cancel_tests_button = QPushButton("Cancel")
        self.cancel_tests_button.setEnabled(False)
        self.cancel_tests_button.clicked.connect(self._cancel_tests)
        run_controls.addWidget(self.run_suite_button)
        run_controls.addWidget(self.run_tests_button)
        run_controls.addWidget(self.cancel_tests_button)
        run_controls.addStretch(1)
        layout.addLayout(run_controls)

        select_controls = QHBoxLayout()
        select_controls.addWidget(QLabel("Preset:"))
        self.suite_preset_combo = QComboBox()
        self.suite_preset_combo.addItem("Custom selection", None)
        self.suite_preset_combo.setItemData(
            0,
            "Select individual tests below, or pick a preset to select a whole "
            "suite.",
            Qt.ItemDataRole.ToolTipRole,
        )
        for suite in TEST_SUITES:
            self.suite_preset_combo.addItem(suite.title, suite.key)
            self.suite_preset_combo.setItemData(
                self.suite_preset_combo.count() - 1,
                suite.description,
                Qt.ItemDataRole.ToolTipRole,
            )
        self.suite_preset_combo.activated.connect(self._on_suite_preset_activated)
        self.select_all_tests_button = QPushButton("Select all tests")
        self.select_all_tests_button.clicked.connect(self._select_all_tests)
        self.deselect_all_tests_button = QPushButton("Deselect all tests")
        self.deselect_all_tests_button.clicked.connect(self._deselect_all_tests)
        select_controls.addWidget(self.suite_preset_combo)
        select_controls.addWidget(self.select_all_tests_button)
        select_controls.addWidget(self.deselect_all_tests_button)
        select_controls.addStretch(1)
        layout.addLayout(select_controls)

        dut_controls = QHBoxLayout()
        dut_controls.addWidget(QLabel("Device under test:"))
        self.dut_combo = QComboBox()
        self.dut_combo.setMinimumWidth(320)
        self.dut_combo.setToolTip(
            "The device the validation suite runs against. State-changing tests are "
            "only ever sent to this one unicast target."
        )
        self.dut_combo.currentIndexChanged.connect(self._on_dut_changed)
        dut_controls.addWidget(self.dut_combo, 1)
        layout.addLayout(dut_controls)

        self.test_selection_label = QLabel()
        self.test_selection_label.setWordWrap(True)
        layout.addWidget(self.test_selection_label)
        self.test_write_declaration_label = QLabel()
        self.test_write_declaration_label.setWordWrap(True)
        self.test_write_declaration_label.setTextFormat(Qt.TextFormat.RichText)
        self.test_write_declaration_label.setStyleSheet(
            "background:#fff0ee;border:1px solid #f3c0b8;border-radius:8px;"
            "padding:8px 10px;color:#8c1d12;"
        )
        self.test_write_declaration_label.setVisible(False)
        layout.addWidget(self.test_write_declaration_label)
        self.test_status_label = QLabel("Idle.")
        self.test_status_label.setWordWrap(True)
        layout.addWidget(self.test_status_label)

        splitter = QSplitter(Qt.Orientation.Vertical)
        tests_group = QGroupBox("Available tests")
        tests_layout = QVBoxLayout(tests_group)
        self.test_table = QTableWidget(0, 5)
        self.test_table.setHorizontalHeaderLabels(
            ["Run", "ID", "Test", "Mode", "Description"]
        )
        self._configure_table(self.test_table, single=False)
        for column in range(4):
            self.test_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        self.test_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        tests_layout.addWidget(self.test_table)

        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        self.test_results_table = QTableWidget(0, 6)
        self.test_results_table.setHorizontalHeaderLabels(
            ["ID", "Test", "Category", "Status", "ms", "Detail"]
        )
        self._configure_table(self.test_results_table, single=False)
        for column in range(5):
            self.test_results_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        self.test_results_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        results_layout.addWidget(self.test_results_table)
        self.test_summary_label = QLabel("No tests run.")
        results_layout.addWidget(self.test_summary_label)

        splitter.addWidget(tests_group)
        splitter.addWidget(results_group)
        splitter.setSizes([390, 330])
        layout.addWidget(splitter, 1)
        self._populate_test_cases()
        self.test_table.itemChanged.connect(self._on_test_item_changed)
        self._refresh_dut_combo()
        return tab

    # ---------------------------------------------------- catalogue rendering
    def _populate_test_cases(self) -> None:
        self._suppress_test_item_changed = True
        try:
            self.test_table.setRowCount(0)
            self._test_row_by_id: dict[str, int] = {}
            self._group_row_by_category: dict[str, int] = {}
            self._rows_by_category: dict[str, list[int]] = {}
            group_background = QBrush(QColor("#e6ecf3"))
            group_foreground = QBrush(QColor("#243447"))
            disabled_foreground = QBrush(QColor("#94a3b8"))
            guarded_foreground = QBrush(QColor("#a15c00"))
            for category, note, cases in grouped_cases():
                group_row = self.test_table.rowCount()
                self.test_table.insertRow(group_row)
                check = QTableWidgetItem()
                check.setFlags(
                    Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled
                )
                # Every test starts deselected: the operator opts in explicitly.
                check.setCheckState(Qt.CheckState.Unchecked)
                check.setData(self._TEST_ROLE, ("group", category))
                check.setBackground(group_background)
                check.setForeground(group_foreground)
                self.test_table.setItem(group_row, 0, check)
                for column in range(1, 5):
                    item = _item("")
                    item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                    item.setBackground(group_background)
                    item.setForeground(group_foreground)
                    self.test_table.setItem(group_row, column, item)
                count_text = f"{len(cases)} test" + ("" if len(cases) == 1 else "s")
                title_item = self.test_table.item(group_row, 1)
                title_item.setText(f"{category} ({count_text})")
                title_font = title_item.font()
                title_font.setBold(True)
                title_item.setFont(title_font)
                note_item = self.test_table.item(group_row, 4)
                note_item.setText(note)
                note_font = note_item.font()
                note_font.setItalic(True)
                note_item.setFont(note_font)

                rows: list[int] = []
                for case in cases:
                    row = self.test_table.rowCount()
                    self.test_table.insertRow(row)
                    rows.append(row)
                    check = QTableWidgetItem()
                    check_flags = Qt.ItemFlag.ItemIsUserCheckable
                    if case.implemented:
                        check_flags |= Qt.ItemFlag.ItemIsEnabled
                    check.setFlags(check_flags)
                    check.setCheckState(Qt.CheckState.Unchecked)
                    check.setData(self._TEST_ROLE, ("test", case.test_id))
                    self.test_table.setItem(row, 0, check)
                    self.test_table.setItem(row, 1, _item(case.test_id, mono=True))
                    self.test_table.setItem(row, 2, _item(case.name))
                    self.test_table.setItem(row, 3, _item(case.mode_text))
                    description = case.description
                    if not case.implemented:
                        description += " — DISABLED in this build."
                    elif not case.default_enabled:
                        description += (
                            " — OPTIONAL: requires configuration mode, a selected target "
                            "and per-operation confirmation."
                        )
                    self.test_table.setItem(row, 4, _item(description))
                    if not case.implemented:
                        for column in range(1, 5):
                            self.test_table.item(row, column).setForeground(
                                disabled_foreground
                            )
                    elif not case.default_enabled:
                        for column in range(1, 5):
                            self.test_table.item(row, column).setForeground(
                                guarded_foreground
                            )
                    self._test_row_by_id[case.test_id] = row
                self._rows_by_category[category] = rows
                self._group_row_by_category[category] = group_row
        finally:
            self._suppress_test_item_changed = False
        self._refresh_test_selection_label()

    # ------------------------------------------------------------ selection
    def _row_is_checked(self, row: int) -> bool:
        item = self.test_table.item(row, 0)
        return item is not None and item.checkState() == Qt.CheckState.Checked

    def _apply_check_states(self, selected: set[str]) -> None:
        """Check exactly ``selected`` and keep every group header consistent."""
        self._suppress_test_item_changed = True
        try:
            for test_id, row in self._test_row_by_id.items():
                item = self.test_table.item(row, 0)
                if item is None or not item.flags() & Qt.ItemFlag.ItemIsEnabled:
                    continue
                item.setCheckState(
                    Qt.CheckState.Checked
                    if test_id in selected
                    else Qt.CheckState.Unchecked
                )
            self._update_group_check_states()
        finally:
            self._suppress_test_item_changed = False
        self._refresh_test_selection_label()

    def _update_group_check_states(self) -> None:
        for category, rows in self._rows_by_category.items():
            checked = sum(1 for row in rows if self._row_is_checked(row))
            if checked == len(rows):
                state = Qt.CheckState.Checked
            elif checked == 0:
                state = Qt.CheckState.Unchecked
            else:
                state = Qt.CheckState.PartiallyChecked
            item = self.test_table.item(self._group_row_by_category[category], 0)
            if item is not None:
                item.setCheckState(state)

    def _on_test_item_changed(self, item: QTableWidgetItem) -> None:
        if self._suppress_test_item_changed or item.column() != 0:
            return
        role = item.data(self._TEST_ROLE)
        if not isinstance(role, tuple) or len(role) != 2:
            return
        kind, value = role
        self._suppress_test_item_changed = True
        try:
            if kind == "group":
                state = item.checkState()
                if state == Qt.CheckState.PartiallyChecked:
                    # Only this code sets the partial state; ignore the echo.
                    return
                for row in self._rows_by_category.get(str(value), []):
                    child = self.test_table.item(row, 0)
                    if child is not None and child.flags() & Qt.ItemFlag.ItemIsEnabled:
                        child.setCheckState(state)
            else:
                self._update_group_check_states()
        finally:
            self._suppress_test_item_changed = False
        # A manual change is by definition no longer the preset's selection.
        self.suite_preset_combo.setCurrentIndex(0)
        self._refresh_test_selection_label()

    def _matching_suite(self, selected: set[str]) -> TestSuite | None:
        for suite in TEST_SUITES:
            if selected == set(suite_test_ids(suite)):
                return suite
        return None

    def _refresh_test_selection_label(self) -> None:
        selected = self._selected_test_ids()
        suite = self._matching_suite(selected)
        if suite is not None:
            self.test_selection_label.setText(
                f"{suite.title}: {len(selected)} test(s) selected — {suite.description}"
            )
        else:
            total = sum(1 for case in TEST_CASES if case.implemented)
            self.test_selection_label.setText(
                f"Custom selection: {len(selected)} of {total} implemented test(s) "
                "selected."
            )
        self._refresh_write_declaration(selected)

    def _refresh_write_declaration(self, selected: set[str]) -> None:
        writes = [
            case
            for case in TEST_CASES
            if case.test_id in selected and case.test_id.startswith("write.")
        ]
        if not writes:
            self.test_write_declaration_label.setVisible(False)
            self.test_write_declaration_label.setText("")
            return
        dut = self._dut_identity()
        target = (
            f"{dut.mac} · {dut.display_name}"
            if dut is not None
            else "no device under test selected — choose one above"
        )
        operations = ", ".join(case.name for case in writes)
        self.test_write_declaration_label.setText(
            "<b>State-changing tests selected.</b> Starting the run sends to "
            f"<b>{esc(target)}</b>, once each and without retry: {esc(operations)}. "
            "Name and IP come from the Configuration tab, the reset mode from the "
            "Reset tab. Configuration mode must be ON."
        )
        self.test_write_declaration_label.setVisible(True)

    def _on_suite_preset_activated(self, index: int) -> None:
        key = self.suite_preset_combo.itemData(index)
        if not key:
            return
        for suite in TEST_SUITES:
            if suite.key == key:
                self._apply_suite(suite)
                return

    def _apply_suite(self, suite: TestSuite) -> None:
        self._apply_check_states(set(suite_test_ids(suite)))
        index = self.suite_preset_combo.findData(suite.key)
        if index >= 0:
            self.suite_preset_combo.setCurrentIndex(index)
        self._refresh_test_selection_label()

    def _select_all_tests(self) -> None:
        """Check every selectable test, including the state-changing ones.

        State-changing tests still need configuration mode and a declared device
        under test, and every frame is sent once and read back. Tests that are not
        implemented in this build remain disabled and cannot be checked.
        """
        self._apply_check_states(
            {case.test_id for case in TEST_CASES if case.implemented}
        )
        self.suite_preset_combo.setCurrentIndex(0)

    def _deselect_all_tests(self) -> None:
        self._apply_check_states(set())
        self.suite_preset_combo.setCurrentIndex(0)

    def _selected_test_ids(self) -> set[str]:
        return {
            test_id
            for test_id, row in self._test_row_by_id.items()
            if self._row_is_checked(row)
        }

    # ------------------------------------------------------- device under test
    def _refresh_dut_combo(self) -> None:
        """Repopulate the device-under-test list from the latest discovery.

        The device-table selection wins, so picking a device anywhere in the app
        means the same device here; a choice made in this combo survives until the
        table selection or the discovery result changes.
        """
        if not hasattr(self, "dut_combo"):
            return  # window still under construction
        devices = list(getattr(self.latest_discovery, "devices", None) or [])
        selected = self.selected_device
        if selected is not None and all(d.mac != selected.mac for d in devices):
            devices.insert(0, selected)
        preferred = (
            selected.mac if selected is not None else self.dut_combo.currentData()
        )
        self.dut_combo.blockSignals(True)
        try:
            self.dut_combo.clear()
            self.dut_combo.addItem("— no device under test —", None)
            for device in devices:
                self.dut_combo.addItem(
                    f"{device.mac} · {device.display_name}", device.mac
                )
            index = self.dut_combo.findData(preferred) if preferred else -1
            self.dut_combo.setCurrentIndex(index if index >= 0 else 0)
        finally:
            self.dut_combo.blockSignals(False)
        self._refresh_test_selection_label()

    def _on_dut_changed(self, _index: int) -> None:
        self._refresh_test_selection_label()

    def _dut_identity(self) -> DeviceIdentity | None:
        """The declared device under test, falling back to the selected device row."""
        mac = self.dut_combo.currentData()
        if not mac:
            return self.selected_device
        for device in getattr(self.latest_discovery, "devices", None) or []:
            if device.mac == mac:
                return device
        if self.selected_device is not None and self.selected_device.mac == mac:
            return self.selected_device
        return None

    def _write_test_parameters(
        self, test_ids: list[str]
    ) -> tuple[dict[str, dict], str]:
        """Build the write parameters for the selected tests from the tab fields.

        The values are the ones already shown in the Configuration and Reset tabs,
        so the operator sees exactly what will be sent. Returns ``(parameters,
        error)``; a non-empty error must abort the run before any frame is sent.
        """
        parameters: dict[str, dict] = {}
        for test_id in test_ids:
            if test_id == "write.set_name":
                name = self.name_edit.text()
                report = validate_station_name(name)
                if not report.ok:
                    return {}, (
                        "Set NameOfStation: "
                        + report.summary()
                        + " Enter a valid name in the Configuration tab first."
                    )
                parameters[test_id] = {
                    "name": name,
                    "permanent": self.perm_radio.isChecked(),
                }
            elif test_id == "write.set_ip":
                ip = self.ip_edit.text().strip()
                mask = self.mask_edit.text().strip()
                gateway = self.gateway_edit.text().strip()
                report = validate_ip_suite(ip, mask, gateway)
                if not report.ok:
                    return {}, (
                        "Set IP parameters: "
                        + report.summary()
                        + " Enter a valid IPv4 suite in the Configuration tab first."
                    )
                parameters[test_id] = {
                    "ip_address": ip,
                    "subnet_mask": mask,
                    "gateway": gateway,
                    "permanent": self.ip_perm_radio.isChecked(),
                }
            else:
                mode = self.reset_mode_combo.currentData()
                if not isinstance(mode, int) or mode not in SUPPORTED_RESET_MODES:
                    return {}, (
                        "ResetToFactorySettings: select reset mode 1/2/4/8 in the Reset "
                        "tab first; the legacy 05/05 variant is not used by tests."
                    )
                parameters[test_id] = {"reset_mode": int(mode)}
        return parameters, ""

    def _run_device_suite(self) -> None:
        """Select the read/write device validation suite and run it.

        Selecting the device under test and pressing this button is the explicit
        declaration for the suite; the suite still runs through the write service
        (configuration mode, fresh unicast revalidation, read-back) and is fixed
        at import time, so the operator knows exactly which operations run.
        """
        self._apply_suite(DEVICE_VALIDATION_SUITE)
        self._run_tests()

    def _run_tests(self) -> None:
        if self._tests_running():
            return
        if (
            self._discovery_running()
            or self._get_running()
            or self._write_running()
            or self._post_check_running()
        ):
            QMessageBox.information(
                self,
                "Another operation is running",
                "Wait for discovery, Get, configuration, or reset to finish or cancel it "
                "before running tests.",
            )
            return
        if self.transport is None or self.current_interface is None:
            QMessageBox.warning(self, "No interface", "Select an interface first.")
            return
        selected = self._selected_test_ids()
        implemented = {c.test_id for c in TEST_CASES if c.implemented}
        selected &= implemented
        if not selected:
            QMessageBox.information(
                self, "No tests selected", "Select at least one implemented test."
            )
            return

        # Record which preset (if any) this run corresponds to, so the event log
        # and the summary can name it instead of only counting results.
        self._last_suite = self._matching_suite(selected)
        dut = self._dut_identity()
        write_tests = selected & {"write.set_name", "write.set_ip", "write.reset"}
        write_authorizations: dict[str, WriteAuthorization] = {}
        write_parameters: dict[str, dict] = {}
        if write_tests:
            if dut is None:
                QMessageBox.warning(
                    self,
                    "No device under test",
                    "Select the device under test in the Test Runner before running "
                    "state-changing tests.",
                )
                return
            if not self.safety_gate.configuration_mode:
                QMessageBox.warning(
                    self,
                    "Configuration mode off",
                    "Enable configuration mode before running state-changing tests.",
                )
                return
            write_parameters, error = self._write_test_parameters(sorted(write_tests))
            if error:
                QMessageBox.warning(self, "State-changing test parameters", error)
                return
            # The declared device under test is the authorization for this run:
            # one explicit DUT selection, one button press, and every operation
            # shown in the red declaration line. Each write is still sent once,
            # freshly revalidated inside WriteService, and read back.
            authorization = WriteAuthorization(
                authorization_confirmed=True,
                safe_maintenance_confirmed=True,
            )
            write_authorizations = {test_id: authorization for test_id in write_tests}
            self.event_log.warning(
                "safety.dut_declared",
                f"Device under test declared; state-changing validation authorized for "
                f"{dut.mac}",
                {
                    "target": dut.mac,
                    "operations": sorted(write_tests),
                    "parameters": write_parameters,
                },
            )

        self.test_cancel = threading.Event()
        runner = TestRunner(
            self.transport,
            self._current_config(),
            event_log=self.event_log,
            discovery_service=self.discovery_service,
            get_service=self.get_service,
            write_service=self.write_service,
            safety_gate=self.safety_gate,
            target=dut,
            write_authorizations=write_authorizations,
            write_parameters=write_parameters,
        )
        worker = TestWorker(runner, selected, self.test_cancel, parent=self)
        worker.finished_ok.connect(self._on_tests_finished)
        worker.failed.connect(self._on_tests_failed)
        worker.progress.connect(self._on_test_progress)
        worker.finished.connect(self._on_test_thread_finished)
        self.test_worker = worker
        self.test_results_table.setRowCount(0)
        self.test_summary_label.setText("Running…")
        self.test_status_label.setText("Running selected tests…")
        self.run_tests_button.setEnabled(False)
        self.run_suite_button.setEnabled(False)
        self.cancel_tests_button.setEnabled(True)
        suite_text = (
            f" [{self._last_suite.title}]" if self._last_suite is not None else ""
        )
        self.event_log.info(
            "tests.start",
            f"Running {len(selected)} functional test(s){suite_text}",
            {
                "tests": sorted(selected),
                "suite": self._last_suite.key if self._last_suite is not None else None,
            },
        )
        worker.start()

    def _cancel_tests(self) -> None:
        self.test_cancel.set()
        self.test_status_label.setText("Cancelling tests…")
        self.event_log.warning("tests.cancel", "Cancellation requested by user")

    def _on_test_progress(self, index: int, total: int, name: str) -> None:
        self.test_status_label.setText(f"Running {index}/{total}: {name}")

    def _on_tests_finished(self, results: list[TestResult]) -> None:
        self.latest_tests = list(results)
        self._refresh_after_state_tests = any(
            result.test_id in {"write.set_name", "write.set_ip", "write.reset"}
            for result in results
        )
        self.test_results_table.setRowCount(0)
        colors = {
            "passed": "#155c38",
            "failed": "#8c1d12",
            "skipped": "#5b6472",
            "inconclusive": "#744800",
        }
        for result in results:
            row = self.test_results_table.rowCount()
            self.test_results_table.insertRow(row)
            self.test_results_table.setItem(row, 0, _item(result.test_id, mono=True))
            self.test_results_table.setItem(row, 1, _item(result.name))
            self.test_results_table.setItem(row, 2, _item(result.category))
            status_item = _item(result.status.upper())
            status_item.setForeground(QBrush(QColor(colors.get(result.status, "#17212b"))))
            self.test_results_table.setItem(row, 3, status_item)
            self.test_results_table.setItem(row, 4, _item(f"{result.duration_ms:.1f}"))
            self.test_results_table.setItem(row, 5, _item(result.detail))
        counts = {
            key: sum(1 for r in results if r.status == key)
            for key in ("passed", "failed", "skipped", "inconclusive")
        }
        summary = (
            f"Passed {counts['passed']} · Failed {counts['failed']} · "
            f"Skipped {counts['skipped']} · Inconclusive {counts['inconclusive']}"
        )
        if self._last_suite is not None:
            summary = f"{self._last_suite.title}: {summary}"
        self.test_summary_label.setText(summary)
        self.test_status_label.setText("Tests finished.")
        self.event_log.info("tests.finished", self.test_summary_label.text(), counts)
        self._update_report_preview()

    def _on_tests_failed(self, message: str) -> None:
        self.test_status_label.setText("Test run failed.")
        self.event_log.error("tests.failed", message)
        QMessageBox.critical(self, "Test run failed", message)

    def _on_test_thread_finished(self) -> None:
        if self.test_worker is not None:
            self.test_worker.deleteLater()
        self.test_worker = None
        self._update_capture_controls()
        if self._refresh_after_state_tests and not self._closing:
            self._refresh_after_state_tests = False
            self.test_status_label.setText(
                "State-changing tests finished; refreshing the device table with one "
                "read-only Identify…"
            )
            QTimer.singleShot(0, lambda: self._start_discovery(apply_filter=False))
