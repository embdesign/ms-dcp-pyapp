"""Monitor tab: repeated Identify sampling with identity change detection.

The tab is a thin surface over ``SessionController.monitor``; the loop itself
lives in ``services/monitor.py`` and runs in a ``QThread`` worker.
"""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from ...html_render import esc
from ...model import iso_utc
from ...monitor import (
    MAX_MONITOR_CYCLES,
    MAX_MONITOR_INTERVAL_S,
    MIN_MONITOR_INTERVAL_S,
    MonitorConfig,
    MonitorCycle,
    MonitorRun,
)
from ..workers import MonitorWorker
from .common import banner
from .common import table_item as _item

MONITOR_COLUMNS = (
    "Time (UTC)",
    "Change",
    "MAC address",
    "NameOfStation",
    "Field",
    "Before",
    "After",
)


class MonitorTabMixin:
    # ------------------------------------------------------------------ build
    def _build_monitor_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(
            banner(
                "<b>Read-only monitoring.</b> Repeats the normal Identify request at a "
                "fixed interval and reports devices that appear, disappear, or whose "
                "NameOfStation / IP / role data changed. One cycle is one Identify "
                "transaction; nothing is written to any device.",
                "Info",
            )
        )

        sampling_group = QGroupBox("Sampling")
        splitter_layout = QHBoxLayout(sampling_group)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.monitor_interval_spin = QDoubleSpinBox()
        self.monitor_interval_spin.setRange(MIN_MONITOR_INTERVAL_S, MAX_MONITOR_INTERVAL_S)
        self.monitor_interval_spin.setSingleStep(1.0)
        self.monitor_interval_spin.setDecimals(1)
        self.monitor_interval_spin.setSuffix(" s")
        self.monitor_interval_spin.setValue(5.0)
        self.monitor_interval_spin.setToolTip(
            "Minimum time between the start of two Identify cycles."
        )
        self.monitor_timeout_spin = QDoubleSpinBox()
        self.monitor_timeout_spin.setRange(0.5, 60.0)
        self.monitor_timeout_spin.setSingleStep(0.5)
        self.monitor_timeout_spin.setDecimals(1)
        self.monitor_timeout_spin.setSuffix(" s")
        self.monitor_timeout_spin.setValue(self.config.timeout_s)
        self.monitor_delay_spin = QSpinBox()
        self.monitor_delay_spin.setRange(1, 6400)
        self.monitor_delay_spin.setValue(self.config.response_delay_factor)
        self.monitor_delay_spin.setSuffix(" × 10 ms")
        self.monitor_vlan_spin = QSpinBox()
        self.monitor_vlan_spin.setRange(0, 4094)
        self.monitor_vlan_spin.setSpecialValueText("untagged")
        self.monitor_vlan_spin.setValue(int(self.config.vlan_id or 0))
        self.monitor_cycles_spin = QSpinBox()
        self.monitor_cycles_spin.setRange(0, MAX_MONITOR_CYCLES)
        self.monitor_cycles_spin.setSpecialValueText("until stopped")
        self.monitor_cycles_spin.setValue(0)
        form.addRow("Interval", self.monitor_interval_spin)
        form.addRow("Timeout per cycle", self.monitor_timeout_spin)
        form.addRow("ResponseDelayFactor", self.monitor_delay_spin)
        form.addRow("VLAN (802.1Q)", self.monitor_vlan_spin)
        form.addRow("Cycles", self.monitor_cycles_spin)

        controls = QVBoxLayout()
        rate = QLabel(
            "Pacing: requests still pass the shared "
            f"{self.config.min_request_interval_s:.1f} s limiter; a cycle that takes "
            "longer than the interval starts the next one immediately."
        )
        rate.setWordWrap(True)
        controls.addWidget(rate)
        buttons = QHBoxLayout()
        self.start_monitor_button = QPushButton("Start monitoring")
        self.start_monitor_button.setObjectName("primary")
        self.start_monitor_button.setToolTip(
            "Begin repeated read-only Identify cycles on the selected interface."
        )
        self.start_monitor_button.clicked.connect(self._start_monitor)
        self.stop_monitor_button = QPushButton("Stop monitoring")
        self.stop_monitor_button.setEnabled(False)
        self.stop_monitor_button.clicked.connect(self._stop_monitor)
        buttons.addWidget(self.start_monitor_button)
        buttons.addWidget(self.stop_monitor_button)
        buttons.addStretch(1)
        controls.addLayout(buttons)
        self.monitor_state_label = QLabel("Idle. No monitor run yet.")
        self.monitor_state_label.setWordWrap(True)
        controls.addWidget(self.monitor_state_label)
        self.monitor_cycle_label = QLabel("No cycles completed.")
        self.monitor_cycle_label.setWordWrap(True)
        controls.addWidget(self.monitor_cycle_label)
        controls.addStretch(1)

        splitter_layout.addLayout(form, 2)
        splitter_layout.addLayout(controls, 3)
        layout.addWidget(sampling_group)

        changes_group = QGroupBox("Detected changes (this run)")
        changes_layout = QVBoxLayout(changes_group)
        self.monitor_changes_table = QTableWidget(0, len(MONITOR_COLUMNS))
        self.monitor_changes_table.setHorizontalHeaderLabels(list(MONITOR_COLUMNS))
        self._configure_table(self.monitor_changes_table, single=False)
        self.monitor_changes_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        for index, width in enumerate((170, 90, 140, 170, 120, 130, 130)):
            self.monitor_changes_table.setColumnWidth(index, width)
        changes_layout.addWidget(self.monitor_changes_table, 1)
        self.monitor_changes_label = QLabel("0 change(s) recorded.")
        changes_layout.addWidget(self.monitor_changes_label)

        # Filled in by a run: this is live feedback, not a static notice.
        self.monitor_notes_label = banner("", "Warning", notice=False)
        self.monitor_notes_label.setVisible(False)
        changes_layout.addWidget(self.monitor_notes_label)
        layout.addWidget(changes_group, 1)
        return tab

    # ------------------------------------------------------------------- flow
    def _monitor_running(self) -> bool:
        return self.monitor_worker is not None

    def _start_monitor(self) -> None:
        if self._closing or self._monitor_running():
            return
        if (
            self._discovery_running()
            or self._tests_running()
            or self._get_running()
            or self._write_running()
            or self._post_check_running()
        ):
            QMessageBox.information(
                self,
                "Another operation is running",
                "Wait for the current discovery, Get, test, configuration or reset "
                "operation to finish (or cancel it) before starting the monitor.",
            )
            return
        if self.transport is None or self.monitor_service is None:
            QMessageBox.warning(self, "No interface", "Select an interface first.")
            return
        if not self.transport.is_capturing and not self._start_capture():
            return

        cfg = MonitorConfig(
            interval_s=self.monitor_interval_spin.value(),
            timeout_s=self.monitor_timeout_spin.value(),
            response_delay_factor=self.monitor_delay_spin.value(),
            vlan_id=self.monitor_vlan_spin.value() or None,
            cycles=self.monitor_cycles_spin.value(),
        )
        self.monitor_cancel = threading.Event()
        worker = MonitorWorker(self.controller, cfg, self.monitor_cancel, parent=self)
        worker.cycle.connect(self._on_monitor_cycle)
        worker.finished_ok.connect(self._on_monitor_finished)
        worker.failed.connect(self._on_monitor_failed)
        worker.progress.connect(self._on_monitor_progress)
        worker.finished.connect(self._on_monitor_thread_finished)
        self.monitor_worker = worker

        self.monitor_changes_table.setRowCount(0)
        self.monitor_changes_label.setText("0 change(s) recorded.")
        self.monitor_notes_label.setVisible(False)
        self.monitor_state_label.setText(
            "Monitoring: Identify every "
            f"{cfg.interval_s:.1f} s"
            + (
                f", {cfg.cycles} cycle(s)"
                if cfg.cycles
                else ", until stopped"
            )
            + "…"
        )
        self.monitor_cycle_label.setText("Waiting for the first cycle…")
        self.event_log.info(
            "monitor.start",
            "Monitor started",
            {
                "interface": self.current_interface.id if self.current_interface else None,
                "config": cfg.to_dict(),
            },
        )
        self._update_capture_controls()
        self.stop_monitor_button.setEnabled(True)
        worker.start()

    def _stop_monitor(self, *, silent: bool = False) -> None:
        if not self._monitor_running():
            return
        self.monitor_cancel.set()
        self.stop_monitor_button.setEnabled(False)
        self.monitor_state_label.setText("Stopping after the current cycle…")
        if not silent:
            self.event_log.warning("monitor.cancel", "Monitor stop requested by user")

    @Slot(object)
    def _on_monitor_cycle(self, cycle: MonitorCycle) -> None:
        if self.monitor_worker is None:
            # A cycle emitted before an interface switch was queued; drop it so
            # the new session's tables stay clean.
            return
        self.controller.ingest_devices(cycle.devices)
        self.monitor_cycle_label.setText(
            f"Cycle {cycle.index + 1}: {cycle.device_count} device(s), "
            f"{len(cycle.changes)} change(s) · {cycle.outcome_text} · "
            f"{cycle.duration_ms:.0f} ms"
        )
        for change in cycle.changes:
            row = self.monitor_changes_table.rowCount()
            self.monitor_changes_table.insertRow(row)
            values = [
                (iso_utc(change.timestamp) or "", True),
                (str(change.kind), False),
                (change.mac, True),
                (change.device_text, False),
                (change.field_label or "—", False),
                (change.before or "—", True),
                (change.after or "—", True),
            ]
            for column, (text, mono) in enumerate(values):
                self.monitor_changes_table.setItem(
                    row, column, _item(text, mono=mono)
                )
        self.monitor_changes_table.scrollToBottom()
        self.monitor_changes_label.setText(
            f"{self.monitor_changes_table.rowCount()} change(s) recorded."
        )
        if cycle.warnings:
            self.monitor_notes_label.setText(
                "<b>Cycle notes</b><br>"
                + "<br>".join(f"• {esc(w)}" for w in cycle.warnings)
            )
            self.monitor_notes_label.setVisible(True)

    def _on_monitor_progress(self, message: str) -> None:
        self.monitor_state_label.setText(esc(message))

    def _on_monitor_finished(self, run: MonitorRun) -> None:
        if self.monitor_worker is None:
            return
        self.latest_monitor = run
        state = "cancelled" if run.cancelled else "finished"
        detail = (
            f"Monitor {state}: {len(run.cycles)} cycle(s), "
            f"{len(run.changes)} change(s)."
        )
        if run.error:
            detail += f" Error: {run.error}"
        self.monitor_state_label.setText(detail)
        self.event_log.info(
            "monitor.finished",
            detail,
            {
                "cycles": len(run.cycles),
                "changes": len(run.changes),
                "cancelled": run.cancelled,
                "error": run.error,
            },
        )
        self._update_capture_controls()

    def _on_monitor_failed(self, message: str) -> None:
        self.monitor_state_label.setText(f"Monitor failed: {message}")
        self.event_log.error("monitor.failed", message)
        QMessageBox.critical(self, "Monitor failed", message)
        self._update_capture_controls()

    def _on_monitor_thread_finished(self) -> None:
        if self.monitor_worker is not None:
            self.monitor_worker.deleteLater()
        self.monitor_worker = None
        self.stop_monitor_button.setEnabled(False)
        self._update_capture_controls()
