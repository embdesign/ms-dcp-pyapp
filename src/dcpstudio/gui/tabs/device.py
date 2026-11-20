"""Device Details tab construction, Get and Signal orchestration."""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...html_render import esc
from ...model import DeviceIdentity, DiscoveryResult, GetResult, WriteResult, iso_utc
from ...services.get import GET_PRESETS, GetConfig, selector_name
from ...utils import hexdump, pretty_json
from ..presentation import device_summary_html, get_result_html
from ..workers import GetWorker, SignalWorker
from .common import apply_mono_font, banner
from .common import display_addr_text as _display_addr
from .common import table_item as _item


class DeviceTabMixin:
    def _build_device_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(
            banner(
                "Identity comes from DCP Identify responses and read-only Get reads. "
                "Unknown/vendor-specific blocks are preserved but not interpreted. "
                "Capability is not inferred from the manufacturer name.",
                "Info",
            )
        )
        controls = QHBoxLayout()
        self.copy_mac_button = QPushButton("Copy MAC")
        self.copy_mac_button.setEnabled(False)
        self.copy_mac_button.clicked.connect(self._copy_device_mac)
        self.copy_json_button = QPushButton("Copy identity JSON")
        self.copy_json_button.setEnabled(False)
        self.copy_json_button.clicked.connect(self._copy_device_json)
        self.unicast_identify_button = QPushButton("Unicast Identify")
        self.unicast_identify_button.setEnabled(False)
        self.unicast_identify_button.setToolTip(
            "Read-only: send the same Identify-All PDU to the selected device MAC."
        )
        self.unicast_identify_button.clicked.connect(self._unicast_identify_selected)
        self.signal_button = QPushButton("Signal device (flash LED)…")
        self.signal_button.setEnabled(False)
        self.signal_button.setToolTip(
            "DCP Signal 05/03: asks the selected device to flash its identification "
            "LED once. One unicast frame; changes no stored configuration."
        )
        self.signal_button.clicked.connect(self._start_signal)
        controls.addWidget(self.copy_mac_button)
        controls.addWidget(self.copy_json_button)
        controls.addWidget(self.unicast_identify_button)
        controls.addWidget(self.signal_button)
        controls.addStretch(1)
        layout.addLayout(controls)
        self.signal_result_label = QLabel("")
        self.signal_result_label.setWordWrap(True)
        self.signal_result_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self.signal_result_label)
        self.detail_title = QLabel("No device selected")
        self.detail_title.setStyleSheet("font-size: 16px; font-weight: 700; padding: 4px;")
        layout.addWidget(self.detail_title)

        get_group = QGroupBox("Read-only Get (no configuration changes)")
        get_layout = QVBoxLayout(get_group)
        get_row = QHBoxLayout()
        self.get_preset_combo = QComboBox()
        for preset in GET_PRESETS.values():
            self.get_preset_combo.addItem(preset.label, preset.key)
        self.get_preset_combo.setToolTip(
            "Select the DCP blocks to read. A Get request is read-only and is sent "
            "only to the explicitly selected device MAC."
        )
        self.get_blocks_button = QPushButton("Get blocks")
        self.get_blocks_button.setObjectName("primary")
        self.get_blocks_button.setEnabled(False)
        self.get_blocks_button.clicked.connect(self._start_get)
        self.cancel_get_button = QPushButton("Cancel Get")
        self.cancel_get_button.setEnabled(False)
        self.cancel_get_button.clicked.connect(self._cancel_get)
        get_row.addWidget(self.get_preset_combo, 1)
        get_row.addWidget(self.get_blocks_button)
        get_row.addWidget(self.cancel_get_button)
        get_layout.addLayout(get_row)
        self.get_result_label = QLabel("No Get request yet.")
        self.get_result_label.setWordWrap(True)
        self.get_result_label.setTextFormat(Qt.TextFormat.RichText)
        get_layout.addWidget(self.get_result_label)
        layout.addWidget(get_group)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        summary_group = QGroupBox("Decoded identity")
        summary_layout = QVBoxLayout(summary_group)
        self.detail_summary = QTextBrowser()
        self.detail_summary.setOpenExternalLinks(False)
        summary_layout.addWidget(self.detail_summary)

        right = QSplitter(Qt.Orientation.Vertical)
        blocks_group = QGroupBox("DCP blocks")
        blocks_layout = QVBoxLayout(blocks_group)
        self.block_tree = QTreeWidget()
        self.block_tree.setHeaderLabels(
            ["Option", "Sub-option", "Len", "BlockInfo / Qualifier", "Error", "Value hex", "ASCII"]
        )
        self.block_tree.setRootIsDecorated(False)
        self.block_tree.setAlternatingRowColors(True)
        for index, width in enumerate((180, 230, 60, 150, 130, 260, 180)):
            self.block_tree.setColumnWidth(index, width)
        blocks_layout.addWidget(self.block_tree)

        hex_group = QGroupBox("Raw response (hex)")
        hex_layout = QVBoxLayout(hex_group)
        self.detail_hex = QPlainTextEdit()
        self.detail_hex.setReadOnly(True)
        apply_mono_font(self.detail_hex)
        self.detail_hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        hex_layout.addWidget(self.detail_hex)

        right.addWidget(blocks_group)
        right.addWidget(hex_group)
        right.setSizes([430, 260])
        splitter.addWidget(summary_group)
        splitter.addWidget(right)
        splitter.setSizes([420, 760])
        layout.addWidget(splitter, 1)
        self._show_device(None)
        return tab

    # --------------------------------------------------------------- Get flow
    def _start_get(self) -> None:
        if self._get_running():
            return
        if (
            self._discovery_running()
            or self._tests_running()
            or self._write_running()
            or self._post_check_running()
            or self._monitor_running()
        ):
            QMessageBox.information(
                self,
                "Another operation is running",
                "Wait for the current discovery, test, configuration, or reset operation "
                "to finish or cancel it before starting Get.",
            )
            return
        if (
            self.transport is None
            or self.get_service is None
            or self.selected_device is None
        ):
            QMessageBox.warning(self, "No target", "Select one discovered device first.")
            return
        if not self.transport.is_capturing and not self._start_capture():
            return
        preset_key = self.get_preset_combo.currentData()
        preset = GET_PRESETS.get(str(preset_key)) if preset_key else None
        if preset is None:
            QMessageBox.warning(self, "No Get preset", "Select a Get block preset.")
            return
        target = self.selected_device
        cfg = GetConfig(
            timeout_s=self.timeout_spin.value(),
            vlan_id=self.vlan_spin.value() or None,
            selectors=preset.selectors,
            min_request_interval_s=self.config.min_request_interval_s,
        )
        self.get_cancel = threading.Event()
        worker = GetWorker(
            self.controller,
            target.mac,
            cfg,
            self.get_cancel,
            parent=self,
        )
        worker.finished_ok.connect(self._on_get_finished)
        worker.failed.connect(self._on_get_failed)
        worker.progress.connect(self._on_get_progress)
        worker.finished.connect(self._on_get_thread_finished)
        self.get_worker = worker
        self.get_result_label.setText(
            f"Reading <b>{esc(preset.label)}</b> from "
            f"<code>{esc(target.mac)}</code>…"
        )
        self.event_log.info(
            "get.start",
            f"Read-only Get to {target.mac}",
            {
                "target": target.mac,
                "preset": preset.key,
                "selectors": [selector_name(s) for s in preset.selectors],
                "timeout_s": cfg.timeout_s,
                "vlan_id": cfg.vlan_id,
            },
        )
        self._update_capture_controls()
        worker.start()

    def _cancel_get(self) -> None:
        self.get_cancel.set()
        self.get_result_label.setText("Cancelling Get request…")
        self.event_log.warning("get.cancel", "Get cancellation requested by user")

    def _on_get_progress(self, message: str) -> None:
        self.get_result_label.setText(esc(message))

    def _on_get_finished(self, result: GetResult) -> None:
        self.latest_get_result = result
        self.get_runs.append(result)
        if len(self.get_runs) > 50:
            self.get_runs = self.get_runs[-50:]
        self._append_transaction_rows(result.transactions)
        if result.identity is not None:
            key = (result.identity.interface_id, result.identity.mac)
            existing = self.device_cache.get(key)
            if existing is None:
                self.device_cache[key] = result.identity
            else:
                existing.merge(result.identity, count_as_duplicate=False)
            self._populate_device_table()
        self.get_result_label.setText(self._get_result_html(result))
        if result.block_errors:
            self.event_log.warning(
                "get.block_errors",
                f"{len(result.block_errors)} Get block(s) rejected",
                {
                    "xid": result.xid,
                    "target": result.target_mac,
                    "detail": result.block_error_text,
                },
            )
        elif result.state in ("response_received", "late_response"):
            self.event_log.info(
                "get.finished",
                f"Get response received from {result.target_mac}",
                {
                    "xid": result.xid,
                    "blocks": len(result.blocks),
                    "rtt_ms": result.rtt_ms,
                },
            )
        else:
            self.event_log.warning(
                "get.outcome",
                result.outcome_text,
                {
                    "xid": result.xid,
                    "target": result.target_mac,
                    "warnings": result.warnings,
                },
            )
        for warning in result.warnings:
            self.event_log.warning("get.warning", warning, {"xid": result.xid})
        self._update_report_preview()
        self._update_capture_controls()

    def _on_get_failed(self, message: str) -> None:
        self.get_result_label.setText(
            f"<span style='color:#8c1d12'><b>Get failed.</b> {esc(message)}</span>"
        )
        self.event_log.error("get.failed", message)
        QMessageBox.critical(self, "Get failed", message)
        self._update_capture_controls()

    def _on_get_thread_finished(self) -> None:
        if self.get_worker is not None:
            self.get_worker.deleteLater()
        self.get_worker = None
        self._update_capture_controls()

    def _get_result_html(self, result: GetResult) -> str:
        return get_result_html(result)

    def _ingest_result(self, result: DiscoveryResult) -> None:
        self.controller.ingest_devices(result.devices)

    def _devices_for_current_interface(self) -> list[DeviceIdentity]:
        if self.current_interface is None:
            return []
        values = [
            d
            for key, d in self.device_cache.items()
            if key[0] == self.current_interface.id
        ]
        values.sort(key=lambda d: d.last_seen, reverse=True)
        return values

    def _populate_device_table(self) -> None:
        selected_mac = self.selected_device.mac if self.selected_device else None
        devices = self._devices_for_current_interface()
        self.device_table.setRowCount(0)
        for device in devices:
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            values = [
                (device.mac, True),
                (device.display_name, False),
                (device.ip_text, True),
                (_display_addr(device.subnet_mask), True),
                (_display_addr(device.gateway), True),
                (
                    f"0x{device.vendor_id:04x}"
                    if device.vendor_id is not None
                    else "—",
                    True,
                ),
                (
                    f"0x{device.device_id:04x}"
                    if device.device_id is not None
                    else "—",
                    True,
                ),
                (device.role_text, False),
                (device.options_text, True),
                (device.interface_id, False),
                (iso_utc(device.last_seen) or "—", True),
            ]
            for column, (text, mono) in enumerate(values):
                self.device_table.setItem(
                    row,
                    column,
                    _item(str(text), mono=mono, data=device if column == 0 else None),
                )
        self.device_count_label.setText(
            f"{len(devices)} device(s) known on this interface · "
            f"{len(self.latest_discovery.devices) if self.latest_discovery else 0} "
            "in latest run"
        )
        if devices:
            target_row = 0
            if selected_mac:
                for row, device in enumerate(devices):
                    if device.mac == selected_mac:
                        target_row = row
                        break
            self.device_table.selectRow(target_row)
        else:
            self._show_device(None)

    # ----------------------------------------------------------- device view
    def _on_device_selected(self) -> None:
        row = self.device_table.currentRow()
        if row < 0:
            self._show_device(None)
            return
        item = self.device_table.item(row, 0)
        device = item.data(Qt.ItemDataRole.UserRole) if item else None
        self._show_device(device if isinstance(device, DeviceIdentity) else None)

    def _show_device(self, device: DeviceIdentity | None) -> None:
        self.selected_device = device
        has_device = device is not None
        self._sync_config_target()
        # The Test Runner's device under test follows the device-table selection.
        self._refresh_dut_combo()
        self.copy_mac_button.setEnabled(has_device)
        self.copy_json_button.setEnabled(has_device)
        self.unicast_identify_button.setEnabled(
            has_device
            and self.transport is not None
            and not self._discovery_running()
            and not self._tests_running()
            and not self._get_running()
            and not self._monitor_running()
        )
        self.get_blocks_button.setEnabled(
            has_device
            and self.transport is not None
            and self.get_service is not None
            and not self._discovery_running()
            and not self._tests_running()
            and not self._get_running()
            and not self._monitor_running()
        )
        if device is None:
            self.detail_title.setText("No device selected")
            self.detail_summary.setHtml(
                "<p style='color:#64748b'>Discover devices, then select exactly one row.</p>"
            )
            self.get_result_label.setText("No device selected.")
            self.block_tree.clear()
            self.detail_hex.clear()
            self._update_config_controls()
            return

        if (
            self.latest_get_result is not None
            and self.latest_get_result.target_mac.lower() == device.mac.lower()
        ):
            self.get_result_label.setText(self._get_result_html(self.latest_get_result))
        else:
            self.get_result_label.setText(
                "No Get request for this device yet. Select a preset and press Get blocks."
            )

        if (
            self.latest_write_result is not None
            and self.latest_write_result.target_mac.lower() == device.mac.lower()
        ):
            if self.latest_write_result.operation == "reset":
                self.reset_result_label.setText(
                    self._write_result_html(self.latest_write_result)
                )
            else:
                self.config_result_label.setText(
                    self._write_result_html(self.latest_write_result)
                )
        else:
            self.config_result_label.setText(
                "No configuration operation for this device in this session."
            )
            self.reset_result_label.setText(
                "No reset operation for this device in this session."
            )
            self.reset_post_check_label.setText("")

        self.detail_title.setText(
            f"{device.display_name} · {device.mac}"
            + (f" · {device.ip_text}" if device.ip_text != "<not set>" else "")
        )
        self.detail_summary.setHtml(device_summary_html(device))

        self.block_tree.clear()
        for block in device.blocks:
            info = "—"
            if block.block_info is not None:
                info = f"info 0x{block.block_info:04x}"
            elif block.block_qualifier is not None:
                info = f"qual 0x{block.block_qualifier:04x}"
            error = "—"
            if block.block_error is not None:
                error = f"0x{block.block_error:02x} {block.error_text or ''}"
            value_hex = block.value[:64].hex()
            if len(block.value) > 64:
                value_hex += "…"
            ascii_value = "".join(
                chr(b) if 32 <= b <= 126 else "." for b in block.value[:64]
            )
            if block.truncated:
                value_hex = "[truncated] " + value_hex
            item = QTreeWidgetItem(
                [
                    block.option_name,
                    block.suboption_name,
                    str(block.block_length),
                    info,
                    error,
                    value_hex,
                    ascii_value,
                ]
            )
            item.setToolTip(5, block.value.hex() if block.value else "")
            if block.unknown:
                for column in range(7):
                    item.setForeground(column, QBrush(QColor("#a15c00")))
            self.block_tree.addTopLevelItem(item)

        try:
            raw = bytes.fromhex(device.last_response_hex)
        except ValueError:
            raw = b""
        if raw:
            self.detail_hex.setPlainText(
                f"Last response — {len(raw)} bytes\n" + hexdump(raw)
            )
        else:
            self.detail_hex.setPlainText("No raw response stored.")
        self._update_config_controls()

    def _copy_device_mac(self) -> None:
        if self.selected_device:
            QApplication.clipboard().setText(self.selected_device.mac)

    def _copy_device_json(self) -> None:
        if self.selected_device:
            QApplication.clipboard().setText(pretty_json(self.selected_device.to_dict()))

    def _unicast_identify_selected(self) -> None:
        if self.selected_device:
            self._start_discovery(unicast_mac=self.selected_device.mac)

    def _start_signal(self) -> None:
        """Flash the selected device's LED: one unicast 05/03 frame.

        Not a state-changing operation: Signal stores nothing, interrupts nothing
        and cannot change device state, so no confirmation dialog is involved. It
        is still one request, unicast only, with no retry.
        """
        if self._signal_running():
            return
        if (
            self._discovery_running()
            or self._tests_running()
            or self._get_running()
            or self._write_running()
            or self._post_check_running()
            or self._monitor_running()
        ):
            QMessageBox.information(
                self,
                "Another operation is running",
                "Wait for the current operation to finish or cancel it before signalling "
                "a device.",
            )
            return
        if (
            self.transport is None
            or self.signal_service is None
            or self.selected_device is None
        ):
            QMessageBox.warning(self, "No target", "Select one discovered device first.")
            return
        if not self.transport.is_capturing and not self._start_capture():
            return
        target = self.selected_device
        self.signal_cancel = threading.Event()
        worker = SignalWorker(
            self.controller,
            target.mac,
            timeout_s=self.timeout_spin.value(),
            vlan_id=self.vlan_spin.value() or None,
            cancel_event=self.signal_cancel,
            parent=self,
        )
        worker.finished_ok.connect(self._on_signal_finished)
        worker.failed.connect(self._on_signal_failed)
        worker.progress.connect(self._on_signal_progress)
        worker.finished.connect(self._on_signal_thread_finished)
        self.signal_worker = worker
        self.signal_button.setEnabled(False)
        self.signal_result_label.setText("Signalling device — waiting for a response…")
        self.event_log.info(
            "signal.start",
            f"Signalling {target.mac} (Control/Signal 05/03, flash once)",
            {"target": target.mac, "operation": "signal"},
        )
        worker.start()

    def _on_signal_progress(self, message: str) -> None:
        self.signal_result_label.setText(esc(message))

    def _on_signal_finished(self, result: WriteResult) -> None:
        self._append_transaction_rows(result.transactions)
        self.signal_result_label.setText(self._signal_result_html(result))
        self.event_log.log(
            "INFO" if result.state == "acknowledged" else "WARNING",
            "signal.finished",
            f"{result.operation_text}: {result.outcome_text}",
            {
                "xid": result.xid,
                "target": result.target_mac,
                "state": result.state,
                "block_error": result.block_error,
            },
        )
        self._update_report_preview()
        self._update_config_controls()

    def _on_signal_failed(self, message: str) -> None:
        self.signal_result_label.setText(
            f"<span style='color:#8c1d12'><b>Signal failed.</b> "
            f"{esc(message)}</span>"
        )
        self.event_log.error("signal.failed", message)
        self._update_config_controls()

    def _on_signal_thread_finished(self) -> None:
        if self.signal_worker is not None:
            self.signal_worker.deleteLater()
        self.signal_worker = None
        self._update_config_controls()
