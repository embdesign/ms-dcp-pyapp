"""Packet Capture tab construction and orchestration."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from ...constants import DCP_BPF_FILTER
from ...html_render import esc
from ...model import CapturedFrame, iso_utc
from ...pcap_io import write_pcap
from ...reporting import SENSITIVE_WARNING, report_filename
from ...utils import hexdump
from ..workers import PcapLoadWorker
from .common import MAX_PACKET_ROWS, PACKET_COLUMNS, apply_mono_font, banner
from .common import table_item as _item


class CaptureTabMixin:
    def _build_capture_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(
            banner(
                f"<b>Capture data is sensitive.</b> {esc(SENSITIVE_WARNING)}",
                "Warning",
            )
        )
        controls = QHBoxLayout()
        self.dcp_only_check = QCheckBox("Show DCP frames only")
        self.dcp_only_check.setChecked(self.config.show_dcp_only)
        self.dcp_only_check.stateChanged.connect(self._repopulate_packet_table)
        self.export_pcap_button = QPushButton("Export PCAP")
        self.export_pcap_button.clicked.connect(self._export_pcap)
        self.load_pcap_button = QPushButton("Load PCAP")
        self.load_pcap_button.clicked.connect(self._load_pcap)
        self.clear_capture_button = QPushButton("Clear capture")
        self.clear_capture_button.clicked.connect(self._clear_capture)
        controls.addWidget(self.dcp_only_check)
        controls.addStretch(1)
        controls.addWidget(self.export_pcap_button)
        controls.addWidget(self.load_pcap_button)
        controls.addWidget(self.clear_capture_button)
        layout.addLayout(controls)
        # The BPF expression shares a row with the statistics so neither is
        # squeezed on a narrow window.
        info_row = QHBoxLayout()
        self.capture_filter_label = QLabel(f"BPF: <code>{esc(DCP_BPF_FILTER)}</code>")
        self.capture_filter_label.setTextFormat(Qt.TextFormat.RichText)
        self.capture_filter_label.setToolTip(f"Capture filter: {DCP_BPF_FILTER}")
        self.capture_filter_label.setMinimumWidth(0)
        info_row.addWidget(self.capture_filter_label)
        info_row.addStretch(1)
        self.packet_stats_label = QLabel("Captured frames: 0")
        info_row.addWidget(self.packet_stats_label)
        layout.addLayout(info_row)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.packet_table = QTableWidget(0, len(PACKET_COLUMNS))
        self.packet_table.setHorizontalHeaderLabels(list(PACKET_COLUMNS))
        self._configure_table(self.packet_table, single=True)
        self.packet_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        for index, width in enumerate((170, 50, 110, 80, 90, 150, 140, 140, 340, 65)):
            self.packet_table.setColumnWidth(index, width)
        self.packet_table.itemSelectionChanged.connect(self._on_packet_selected)
        splitter.addWidget(self.packet_table)

        detail_group = QGroupBox("Frame detail")
        detail_layout = QVBoxLayout(detail_group)
        self.packet_detail_label = QLabel("Select a frame to inspect it.")
        self.packet_detail_label.setWordWrap(True)
        detail_layout.addWidget(self.packet_detail_label)
        self.packet_detail = QPlainTextEdit()
        self.packet_detail.setReadOnly(True)
        apply_mono_font(self.packet_detail)
        self.packet_detail.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        detail_layout.addWidget(self.packet_detail)
        splitter.addWidget(detail_group)
        splitter.setSizes([500, 280])
        layout.addWidget(splitter, 1)
        return tab

    # ---------------------------------------------------------- capture flow
    def _on_transport_frame(self, raw: bytes, timestamp, direction: str) -> None:
        if self.current_interface is None:
            return
        item = self.capture.add(raw, timestamp, direction, self.current_interface.id)
        if self.discovery_service is not None:
            self.discovery_service.process_frame(raw, timestamp, direction)
        if self.get_service is not None:
            self.get_service.process_frame(raw, timestamp, direction)
        if self.write_service is not None:
            self.write_service.process_frame(raw, timestamp, direction)
        if self.signal_service is not None:
            self.signal_service.process_frame(raw, timestamp, direction)
        if item is not None:
            self.capture_bridge.frame_received.emit(item)

    @Slot(object)
    def _on_frame_ui(self, item: CapturedFrame) -> None:
        if not isinstance(item, CapturedFrame):
            return
        if self.tabs.currentWidget() is self.capture_tab and (
            not self.dcp_only_check.isChecked()
            or (item.parsed is not None and item.parsed.is_dcp)
        ):
            self._append_packet_row(item)

    def _append_packet_row(self, item: CapturedFrame) -> None:
        table = self.packet_table
        row = table.rowCount()
        table.insertRow(row)
        parsed = item.parsed
        values = [
            iso_utc(item.timestamp) or "",
            item.direction,
            parsed.kind if parsed else "",
            f"0x{parsed.frame_id:04x}" if parsed and parsed.frame_id is not None else "—",
            parsed.service_name if parsed else "",
            parsed.service_type_name if parsed else "",
            parsed.src_mac if parsed and parsed.src_mac else "—",
            parsed.dst_mac if parsed and parsed.dst_mac else "—",
            parsed.summary() if parsed else "Unparsed",
            str(len(item.raw)),
        ]
        for column, (text, mono) in enumerate(
            [(v, c in (0, 3, 6, 7, 9)) for c, v in enumerate(values)]
        ):
            table.setItem(
                row,
                column,
                _item(text, mono=mono, data=item if column == 0 else None),
            )
        while table.rowCount() > MAX_PACKET_ROWS:
            table.removeRow(0)
        table.scrollToBottom()

    def _repopulate_packet_table(self) -> None:
        self.packet_table.setRowCount(0)
        frames = self.capture.snapshot()
        if self.dcp_only_check.isChecked():
            frames = [f for f in frames if f.parsed is not None and f.parsed.is_dcp]
        for frame in frames[-MAX_PACKET_ROWS:]:
            self._append_packet_row(frame)

    def _on_packet_selected(self) -> None:
        row = self.packet_table.currentRow()
        if row < 0:
            return
        item = self.packet_table.item(row, 0)
        frame = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(frame, CapturedFrame):
            return
        parsed = frame.parsed
        summary = parsed.summary() if parsed else "Unparsed frame"
        lines = [
            f"<b>{esc(summary)}</b>",
            f"Captured {esc(iso_utc(frame.timestamp) or '')} · "
            f"{esc(frame.interface_id)} · {esc(frame.direction)} · "
            f"{len(frame.raw)} bytes",
        ]
        if parsed and parsed.warnings:
            lines.append(
                "<span style='color:#8c1d12'>Warnings: "
                + esc("; ".join(parsed.warnings))
                + "</span>"
            )
        self.packet_detail_label.setText("<br>".join(lines))
        self.packet_detail.setPlainText(hexdump(frame.raw))

    def _toggle_dcp_only(self, *_args) -> None:
        self._repopulate_packet_table()

    def _export_pcap(self) -> None:
        frames = self.capture.snapshot()
        if not frames:
            QMessageBox.information(
                self, "No frames", "There are no captured frames to export."
            )
            return
        default_dir = Path(self.config.report_directory)
        default_dir.mkdir(parents=True, exist_ok=True)
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export capture as PCAP",
            str(default_dir / report_filename("dcp-capture", extension="pcap")),
            "PCAP files (*.pcap);;All files (*)",
        )
        if not filename:
            return
        try:
            count = write_pcap(filename, frames)
        except Exception as exc:
            QMessageBox.critical(self, "PCAP export failed", str(exc))
            self.event_log.error("pcap.export_failed", str(exc))
            return
        self.event_log.info(
            "pcap.exported",
            f"Exported {count} frame(s) to {filename}",
            {"path": filename},
        )
        QMessageBox.information(
            self, "PCAP exported", f"{count} frame(s) written to:\n{filename}"
        )

    def _load_pcap(self) -> None:
        if self.pcap_worker is not None and self.pcap_worker.isRunning():
            return
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load PCAP",
            str(Path.home()),
            "PCAP files (*.pcap *.cap);;All files (*)",
        )
        if not filename:
            return
        worker = PcapLoadWorker(filename, parent=self)
        worker.finished_ok.connect(self._on_pcap_loaded)
        worker.failed.connect(self._on_pcap_failed)
        worker.finished.connect(self._on_pcap_thread_finished)
        self.pcap_worker = worker
        self.load_pcap_button.setEnabled(False)
        self.packet_stats_label.setText("Loading and decoding PCAP…")
        self.event_log.info("pcap.load_start", f"Loading {filename}", {"path": filename})
        worker.start()

    def _on_pcap_loaded(self, frames: list[CapturedFrame], path: str) -> None:
        self.capture.clear()
        dropped = 0
        for frame in frames:
            before = self.capture.total
            self.capture.add(
                frame.raw, frame.timestamp, frame.direction, frame.interface_id
            )
            if self.capture.total == before:
                dropped += 1
        self._repopulate_packet_table()
        self._update_capture_stats()
        self.event_log.info(
            "pcap.loaded",
            f"Loaded {len(frames)} frame(s) from {path}",
            {"path": path, "frames": len(frames), "dropped": dropped},
        )
        if dropped:
            self.event_log.warning(
                "pcap.truncated",
                f"{dropped} frame(s) exceeded the display buffer and were not retained",
            )

    def _on_pcap_failed(self, message: str) -> None:
        self.event_log.error("pcap.load_failed", message)
        QMessageBox.critical(self, "PCAP load failed", message)
        self._update_capture_stats()

    def _on_pcap_thread_finished(self) -> None:
        if self.pcap_worker is not None:
            self.pcap_worker.deleteLater()
        self.pcap_worker = None
        self.load_pcap_button.setEnabled(True)

    def _clear_capture(self) -> None:
        self.capture.clear()
        self.packet_table.setRowCount(0)
        self.packet_detail.clear()
        self.packet_detail_label.setText("Select a frame to inspect it.")
        self._update_capture_stats()
        self.event_log.info("capture.cleared", "Capture buffer cleared")

    # ----------------------------------------------------- capture lifecycle
    def _start_capture(self, silent: bool = False) -> bool:
        if self.transport is None:
            if not silent:
                QMessageBox.warning(self, "No interface", "Select an interface first.")
            return False
        try:
            self.transport.start_capture()
            self.last_readiness = self.transport.readiness()
            self.event_log.info(
                "capture.started",
                f"Passive capture started on {self.current_interface.name if self.current_interface else '?'}",
                {"filter": getattr(self.transport, "used_filter", "")},
            )
            self._update_capture_controls()
            return True
        except Exception as exc:
            self.last_readiness = self.transport.readiness()
            self._update_permission_label()
            self.event_log.error("capture.start_failed", str(exc))
            if not silent:
                QMessageBox.critical(
                    self,
                    "Capture could not start",
                    str(exc)
                    + "\n\nSee docs/troubleshooting.md for Linux CAP_NET_RAW and "
                    "Windows Npcap instructions.",
                )
            return False

    def _stop_capture(self, silent: bool = False) -> None:
        if self.transport is not None and self.transport.is_capturing:
            try:
                self.transport.stop_capture()
                self.event_log.info("capture.stopped", "Passive capture stopped")
            except Exception as exc:
                self.event_log.warning("capture.stop_failed", str(exc))
        self._update_capture_controls()

    def _update_capture_controls(self) -> None:
        capturing = bool(self.transport is not None and self.transport.is_capturing)
        ready = self.transport is not None
        get_running = self._get_running()
        busy = (
            self._discovery_running()
            or self._tests_running()
            or get_running
            or self._write_running()
            or self._post_check_running()
            or self._monitor_running()
        )
        self.start_capture_button.setEnabled(ready and not capturing and not busy)
        self.stop_capture_button.setEnabled(capturing and not busy)
        self.refresh_button.setEnabled(not capturing and not busy)
        self.interface_table.setEnabled(not busy)
        self.discover_button.setEnabled(ready and not busy)
        self.cancel_discovery_button.setEnabled(self._discovery_running())
        self.run_tests_button.setEnabled(ready and not busy)
        self.run_suite_button.setEnabled(ready and not busy)
        self.cancel_tests_button.setEnabled(self._tests_running())
        self.unicast_identify_button.setEnabled(
            self.selected_device is not None and ready and not busy
        )
        self.get_blocks_button.setEnabled(
            self.selected_device is not None
            and ready
            and self.get_service is not None
            and not busy
        )
        self.cancel_get_button.setEnabled(get_running)
        self.get_preset_combo.setEnabled(not get_running)
        if hasattr(self, "start_monitor_button"):
            self.start_monitor_button.setEnabled(
                ready and not busy and not self._monitor_running()
            )
            self.stop_monitor_button.setEnabled(self._monitor_running())
        self.capture_state_label.setText(
            f"Capture: {'running' if capturing else 'stopped'}"
            + (f" · {self.current_interface.name}" if self.current_interface else "")
        )
        self.status_capture.setText(f"Capture: {'running' if capturing else 'stopped'}")
        if self.current_interface:
            self.status_interface.setText(
                f"Interface: {self.current_interface.name} ({self.current_interface.mac or 'no MAC'})"
            )
        else:
            self.status_interface.setText("Interface: none")
        self._update_config_controls()

    def _update_capture_stats(self) -> None:
        stats = self.capture.stats()
        text = (
            f"Captured frames: {stats.get('total', 0)} · DCP: {stats.get('dcp', 0)} · "
            f"other PROFINET: {stats.get('profinet_other', 0)} · other: {stats.get('other', 0)}"
        )
        if stats.get("dropped"):
            text += f" · dropped from display buffer: {stats['dropped']}"
        if hasattr(self, "packet_stats_label"):
            self.packet_stats_label.setText(text)
