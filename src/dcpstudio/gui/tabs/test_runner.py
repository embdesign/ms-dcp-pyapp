"""Test Runner tab construction and orchestration."""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
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
from ...model import TestResult
from ...operations import reset_mode_spec, set_ip_spec, set_name_spec
from ...services.write import WriteAuthorization
from ...testrunner.cases import TEST_CASES
from ...testrunner.runner import TestRunner
from ...validation import validate_ip_suite, validate_station_name
from ..workers import TestWorker
from .common import banner
from .common import table_item as _item


class TestRunnerTabMixin:
    def _build_test_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(
            banner(
                "Functional and interoperability checks, not official PROFINET conformance "
                "certification. Read-only tests transmit Identify/Get frames. Optional "
                "state-changing tests require configuration mode, a selected target, and a "
                "separate confirmation for every operation. Run at most one "
                "state-changing test per test run.",
                "Warning",
            )
        )
        controls = QHBoxLayout()
        self.select_all_tests_button = QPushButton("Select all tests")
        self.select_all_tests_button.clicked.connect(self._select_all_tests)
        self.deselect_all_tests_button = QPushButton("Deselect all tests")
        self.deselect_all_tests_button.clicked.connect(self._deselect_all_tests)
        self.run_tests_button = QPushButton("Run selected tests")
        self.run_tests_button.setObjectName("primary")
        self.run_tests_button.clicked.connect(self._run_tests)
        self.cancel_tests_button = QPushButton("Cancel")
        self.cancel_tests_button.setEnabled(False)
        self.cancel_tests_button.clicked.connect(self._cancel_tests)
        controls.addWidget(self.select_all_tests_button)
        controls.addWidget(self.deselect_all_tests_button)
        controls.addWidget(self.run_tests_button)
        controls.addWidget(self.cancel_tests_button)
        controls.addStretch(1)
        layout.addLayout(controls)
        self.test_status_label = QLabel("Idle.")
        self.test_status_label.setWordWrap(True)
        layout.addWidget(self.test_status_label)

        splitter = QSplitter(Qt.Orientation.Vertical)
        tests_group = QGroupBox("Available tests")
        tests_layout = QVBoxLayout(tests_group)
        self.test_table = QTableWidget(0, 6)
        self.test_table.setHorizontalHeaderLabels(
            ["Run", "ID", "Test", "Category", "Live", "Description"]
        )
        self._configure_table(self.test_table, single=False)
        self.test_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        tests_layout.addWidget(self.test_table)

        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        self.test_results_table = QTableWidget(0, 5)
        self.test_results_table.setHorizontalHeaderLabels(
            ["ID", "Test", "Status", "ms", "Detail"]
        )
        self._configure_table(self.test_results_table, single=False)
        self.test_results_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_results_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_results_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_results_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.test_results_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        results_layout.addWidget(self.test_results_table)
        self.test_summary_label = QLabel("No tests run.")
        results_layout.addWidget(self.test_summary_label)

        splitter.addWidget(tests_group)
        splitter.addWidget(results_group)
        splitter.setSizes([390, 330])
        layout.addWidget(splitter, 1)
        self._populate_test_cases()
        return tab

    # ------------------------------------------------------------- test flow
    def _populate_test_cases(self) -> None:
        self.test_table.setRowCount(0)
        for case in TEST_CASES:
            row = self.test_table.rowCount()
            self.test_table.insertRow(row)
            check = QTableWidgetItem()
            check_flags = Qt.ItemFlag.ItemIsUserCheckable
            if case.implemented:
                check_flags |= Qt.ItemFlag.ItemIsEnabled
            check.setFlags(check_flags)
            # Every test starts deselected: the operator opts in explicitly with
            # the row checkbox, "Select all tests" or "Run selected tests".
            check.setCheckState(Qt.CheckState.Unchecked)
            check.setData(Qt.ItemDataRole.UserRole, case.test_id)
            self.test_table.setItem(row, 0, check)
            self.test_table.setItem(row, 1, _item(case.test_id, mono=True))
            self.test_table.setItem(row, 2, _item(case.name))
            self.test_table.setItem(row, 3, _item(case.category))
            self.test_table.setItem(row, 4, _item("live" if case.live else "offline"))
            description = case.description
            if not case.implemented:
                description += " — DISABLED in this build."
            elif not case.default_enabled:
                description += (
                    " — OPTIONAL: requires configuration mode, a selected target and "
                    "per-operation confirmation."
                )
            self.test_table.setItem(row, 5, _item(description))
            if not case.implemented:
                for column in range(1, 6):
                    item = self.test_table.item(row, column)
                    if item is not None:
                        item.setForeground(QBrush(QColor("#94a3b8")))
            elif not case.default_enabled:
                for column in range(1, 6):
                    item = self.test_table.item(row, column)
                    if item is not None:
                        item.setForeground(QBrush(QColor("#a15c00")))

    def _select_all_tests(self) -> None:
        """Check every selectable test, including the optional guarded ones.

        Guarded tests stay gated: they still need configuration mode, a selected
        target and a per-operation confirmation, and at most one state-changing
        test can run per test run. Tests that are not implemented in this build
        remain disabled and cannot be checked.
        """
        for row in range(self.test_table.rowCount()):
            item = self.test_table.item(row, 0)
            if item is not None and item.flags() & Qt.ItemFlag.ItemIsEnabled:
                item.setCheckState(Qt.CheckState.Checked)

    def _deselect_all_tests(self) -> None:
        for row in range(self.test_table.rowCount()):
            item = self.test_table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Unchecked)

    def _selected_test_ids(self) -> set[str]:
        selected: set[str] = set()
        for row in range(self.test_table.rowCount()):
            item = self.test_table.item(row, 0)
            if item is None:
                continue
            if (
                item.flags() & Qt.ItemFlag.ItemIsUserCheckable
                and item.checkState() == Qt.CheckState.Checked
            ):
                test_id = item.data(Qt.ItemDataRole.UserRole)
                if test_id:
                    selected.add(str(test_id))
        return selected

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

        write_tests = selected & {"write.set_name", "write.set_ip", "write.reset"}
        write_authorizations: dict[str, WriteAuthorization] = {}
        write_parameters: dict[str, dict] = {}
        if write_tests:
            if len(write_tests) > 1:
                QMessageBox.information(
                    self,
                    "One write test per run",
                    "Run at most one state-changing test per test run. Each operation needs "
                    "its own fresh target identity confirmation.",
                )
                return
            if self.selected_device is None:
                QMessageBox.warning(
                    self,
                    "No target",
                    "Select exactly one discovered device before running state-changing tests.",
                )
                return
            if not self.safety_gate.configuration_mode:
                QMessageBox.warning(
                    self,
                    "Configuration mode off",
                    "Enable configuration mode before running state-changing tests.",
                )
                return
            target = self.selected_device
            for test_id in sorted(write_tests):
                if test_id == "write.set_name":
                    name = self.name_edit.text()
                    report = validate_station_name(name)
                    if not report.ok:
                        QMessageBox.warning(
                            self, "Invalid NameOfStation", report.summary()
                        )
                        return
                    permanent = self.perm_radio.isChecked()
                    parameters = {"name": name, "permanent": permanent}
                    spec = set_name_spec(
                        name,
                        permanent=permanent,
                        previous_name=target.name_of_station or "<not set>",
                    )
                elif test_id == "write.set_ip":
                    ip = self.ip_edit.text().strip()
                    mask = self.mask_edit.text().strip()
                    gateway = self.gateway_edit.text().strip()
                    report = validate_ip_suite(ip, mask, gateway)
                    if not report.ok:
                        QMessageBox.warning(self, "Invalid IPv4 suite", report.summary())
                        return
                    permanent = self.ip_perm_radio.isChecked()
                    parameters = {
                        "ip_address": ip,
                        "subnet_mask": mask,
                        "gateway": gateway,
                        "permanent": permanent,
                    }
                    spec = set_ip_spec(
                        ip, mask, gateway, permanent=permanent, previous_ip=target.ip_text
                    )
                else:
                    mode = self.reset_mode_combo.currentData()
                    if not isinstance(mode, int) or mode not in SUPPORTED_RESET_MODES:
                        QMessageBox.warning(
                            self,
                            "Unsupported reset",
                            "The reset test needs one of the numbered modes; select a "
                            "mode 1/2/4/8 instead of the legacy 05/05 variant.",
                        )
                        return
                    mode = int(mode)
                    parameters = {"reset_mode": mode}
                    spec = reset_mode_spec(mode)
                confirmation = self._confirmation_for(spec, target, operation_id=test_id)
                authorization = self._confirm_operation(confirmation)
                if authorization is None:
                    return
                write_authorizations[test_id] = authorization
                write_parameters[test_id] = parameters

        self.test_cancel = threading.Event()
        runner = TestRunner(
            self.transport,
            self._current_config(),
            event_log=self.event_log,
            discovery_service=self.discovery_service,
            get_service=self.get_service,
            write_service=self.write_service,
            safety_gate=self.safety_gate,
            target=self.selected_device,
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
        self.cancel_tests_button.setEnabled(True)
        self.event_log.info(
            "tests.start",
            f"Running {len(selected)} functional test(s)",
            {"tests": sorted(selected)},
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
            status_item = _item(result.status.upper())
            status_item.setForeground(QBrush(QColor(colors.get(result.status, "#17212b"))))
            self.test_results_table.setItem(row, 2, status_item)
            self.test_results_table.setItem(row, 3, _item(f"{result.duration_ms:.1f}"))
            self.test_results_table.setItem(row, 4, _item(result.detail))
        counts = {
            key: sum(1 for r in results if r.status == key)
            for key in ("passed", "failed", "skipped", "inconclusive")
        }
        self.test_summary_label.setText(
            f"Passed {counts['passed']} · Failed {counts['failed']} · "
            f"Skipped {counts['skipped']} · Inconclusive {counts['inconclusive']}"
        )
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
