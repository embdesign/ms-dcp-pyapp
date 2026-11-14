"""Logs & Reports tab construction and report/session orchestration."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ...config import AppConfig
from ...model import LogRecordData, TransactionRecord, iso_utc
from ...reporting import (
    KNOWN_LIMITATIONS,
    SENSITIVE_WARNING,
    ReportContext,
    report_filename,
    write_html_report,
    write_json_report,
)
from ..presentation import report_preview_html
from .common import MAX_LOG_ROWS, banner
from .common import table_item as _item


class LogsTabMixin:
    def _build_logs_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(
            banner(
                "Reports and captures can contain MAC addresses, station names, IP addresses "
                "and network topology. Treat them as sensitive operational data.",
                "Warning",
            )
        )
        controls = QHBoxLayout()
        self.export_json_button = QPushButton("Export JSON report")
        self.export_json_button.setObjectName("primary")
        self.export_json_button.clicked.connect(lambda: self._export_report("json"))
        self.export_html_button = QPushButton("Export HTML report")
        self.export_html_button.clicked.connect(lambda: self._export_report("html"))
        self.clear_session_button = QPushButton("Clear session data")
        self.clear_session_button.clicked.connect(self._clear_session)
        controls.addWidget(self.export_json_button)
        controls.addWidget(self.export_html_button)
        controls.addWidget(self.clear_session_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        inner = QTabWidget()
        events_widget = QWidget()
        events_layout = QVBoxLayout(events_widget)
        self.event_table = QTableWidget(0, 4)
        self.event_table.setHorizontalHeaderLabels(["UTC time", "Level", "Event", "Message"])
        self._configure_table(self.event_table, single=True)
        self.event_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.event_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.event_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.event_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        events_layout.addWidget(self.event_table)
        inner.addTab(events_widget, "Structured event log")

        transactions_widget = QWidget()
        transactions_layout = QVBoxLayout(transactions_widget)
        self.transaction_table = QTableWidget(0, 8)
        self.transaction_table.setHorizontalHeaderLabels(
            ["UTC time", "Event", "Outcome", "Xid", "Service", "Peer", "RTT ms", "Detail"]
        )
        self._configure_table(self.transaction_table, single=True)
        for index in range(7):
            self.transaction_table.horizontalHeader().setSectionResizeMode(
                index, QHeaderView.ResizeMode.ResizeToContents
            )
        self.transaction_table.horizontalHeader().setSectionResizeMode(
            7, QHeaderView.ResizeMode.Stretch
        )
        transactions_layout.addWidget(self.transaction_table)
        inner.addTab(transactions_widget, "Transaction log")

        preview_widget = QWidget()
        preview_layout = QVBoxLayout(preview_widget)
        self.report_preview = QTextBrowser()
        self.report_preview.setOpenExternalLinks(False)
        preview_layout.addWidget(self.report_preview)
        inner.addTab(preview_widget, "Session summary")
        layout.addWidget(inner, 1)
        return tab

    # ----------------------------------------------------------- logs/report
    @Slot(object)
    def _on_log_record(self, record: LogRecordData) -> None:
        if not isinstance(record, LogRecordData):
            return
        row = self.event_table.rowCount()
        self.event_table.insertRow(row)
        self.event_table.setItem(
            row, 0, _item(iso_utc(record.timestamp) or "", mono=True)
        )
        self.event_table.setItem(row, 1, _item(record.level))
        self.event_table.setItem(row, 2, _item(record.event, mono=True))
        self.event_table.setItem(row, 3, _item(record.message))
        while self.event_table.rowCount() > MAX_LOG_ROWS:
            self.event_table.removeRow(0)
        self.event_table.scrollToBottom()

    def _append_transaction_rows(self, transactions: list[TransactionRecord]) -> None:
        new_transactions: list[TransactionRecord] = []
        for transaction in transactions:
            if transaction not in self.transactions:
                self.transactions.append(transaction)
                new_transactions.append(transaction)
        for transaction in new_transactions:
            row = self.transaction_table.rowCount()
            self.transaction_table.insertRow(row)
            values = [
                iso_utc(transaction.timestamp) or "",
                transaction.event,
                transaction.outcome,
                f"0x{transaction.xid:08x}" if transaction.xid is not None else "—",
                transaction.service,
                transaction.peer_mac or "—",
                f"{transaction.rtt_ms:.3f}" if transaction.rtt_ms is not None else "—",
                transaction.detail,
            ]
            for column, text in enumerate(values):
                self.transaction_table.setItem(
                    row, column, _item(str(text), mono=column in (0, 2, 3, 5, 6))
                )

    def _current_config(self) -> AppConfig:
        return replace(
            self.config,
            last_interface_id=(
                self.current_interface.id
                if self.current_interface
                else self.config.last_interface_id
            ),
            timeout_s=self.timeout_spin.value(),
            response_delay_factor=self.delay_spin.value(),
            vlan_id=self.vlan_spin.value() or None,
            show_dcp_only=self.dcp_only_check.isChecked(),
        )

    def _report_context(self) -> ReportContext:
        return ReportContext(
            interface=self.current_interface,
            readiness=self.last_readiness,
            config=self._current_config(),
            discovery=self.latest_discovery,
            discoveries=list(self.discovery_runs),
            get_results=list(self.get_runs),
            write_results=list(self.write_runs),
            test_results=list(self.latest_tests),
            logs=self.event_log.snapshot(),
            capture_stats=self.capture.stats(),
            extra_notes=list(self._session_notes),
        )

    def _export_report(self, kind: str) -> None:
        try:
            default_dir = Path(self.config.report_directory)
            default_dir.mkdir(parents=True, exist_ok=True)
            extension = "json" if kind == "json" else "html"
            filename, _ = QFileDialog.getSaveFileName(
                self,
                f"Export {kind.upper()} report",
                str(default_dir / report_filename("dcp-report", extension=extension)),
                "JSON files (*.json);;All files (*)"
                if kind == "json"
                else "HTML files (*.html);;All files (*)",
            )
            if not filename:
                return
            context = self._report_context()
            if kind == "json":
                path = write_json_report(filename, context)
            else:
                path = write_html_report(filename, context)
            self.event_log.info(
                "report.exported",
                f"{kind.upper()} report written to {path}",
                {"path": str(path)},
            )
            QMessageBox.information(
                self, "Report exported", f"Report written to:\n{path}"
            )
        except Exception as exc:
            self.event_log.error("report.failed", str(exc))
            QMessageBox.critical(self, "Report export failed", str(exc))

    def _update_report_preview(self) -> None:
        devices = self._devices_for_current_interface()
        counts = {
            status: sum(1 for r in self.latest_tests if r.status == status)
            for status in ("passed", "failed", "skipped", "inconclusive")
        }
        self.report_preview.setHtml(
            report_preview_html(
                interface_name=(
                    self.current_interface.name if self.current_interface else None
                ),
                capture_total=self.capture.total,
                devices=devices,
                get_count=len(self.get_runs),
                write_count=len(self.write_runs),
                status_counts=counts,
                limitations=KNOWN_LIMITATIONS,
                sensitive_warning=SENSITIVE_WARNING,
            )
        )

    def _clear_session(self) -> None:
        if (
            self._discovery_running()
            or self._get_running()
            or self._tests_running()
            or self._write_running()
            or self._post_check_running()
        ):
            QMessageBox.information(
                self,
                "Operation in progress",
                "Wait for the current operation to finish before clearing session data.",
            )
            return
        answer = QMessageBox.question(
            self,
            "Clear session data",
            "Clear captured frames, discovery results, test results, and logs from this "
            "window? Exported files are not deleted. No network frame will be sent.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.capture.clear()
        self.device_cache.clear()
        self.selected_device = None
        self.latest_discovery = None
        self.discovery_runs.clear()
        self.latest_get_result = None
        self.get_runs.clear()
        self.latest_write_result = None
        self.latest_reset_result = None
        self.write_runs.clear()
        self.safety_gate.disable_configuration_mode()
        self.transactions.clear()
        self.latest_tests = []
        self.event_log.clear()
        self.device_table.setRowCount(0)
        self.packet_table.setRowCount(0)
        self.packet_detail.clear()
        self.packet_detail_label.setText("Select a frame to inspect it.")
        self.transaction_table.setRowCount(0)
        self.test_results_table.setRowCount(0)
        self.event_table.setRowCount(0)
        self.test_summary_label.setText("No tests run.")
        self.discovery_summary_label.setText("No discovery run yet.")
        self.discovery_warning_label.setVisible(False)
        self.config_result_label.setText(
            "No configuration operation has been sent in this session."
        )
        self.reset_result_label.setText(
            "No reset operation has been sent in this session."
        )
        self.reset_post_check_label.setText("")
        self._show_device(None)
        self._update_capture_stats()
        self._update_report_preview()
        self.event_log.info("session.cleared", "Session data cleared")
