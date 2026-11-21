"""Interfaces & Discovery tab construction and interface lifecycle."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from ...html_render import esc
from ...interfaces import InterfaceInfo
from ...inventory import (
    compare_plan,
    device_matches_filter,
    inventory_csv,
    parse_plan_csv,
)
from ...model import DeviceIdentity, DiscoveryResult
from ...services.discovery import DiscoveryConfig, IdentifyFilter
from ...transport.interfaces import enumerate_interfaces
from ...validation import validate_station_name
from ..workers import DiscoveryWorker
from .common import DEVICE_COLUMNS, banner
from .common import table_item as _item


class DiscoveryTabMixin:
    def _build_discovery_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(
            banner(
                "<b>Layer 2 only.</b> DCP does not traverse IP routers. Select the NIC on the "
                "same broadcast domain (and VLAN) as the devices. Discovery is user-triggered; "
                "no continuous scanning is performed and discovery itself sends no "
                "state-changing frame.",
                "Info",
            )
        )

        splitter = QSplitter(Qt.Orientation.Vertical)

        top = QWidget()
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(12)

        iface_group = QGroupBox("1 · Local interfaces")
        iface_layout = QVBoxLayout(iface_group)
        self.interface_table = QTableWidget(0, 6)
        self.interface_table.setHorizontalHeaderLabels(
            ["Interface", "MAC", "IP addresses", "Link", "Type", "Ready"]
        )
        self._configure_table(self.interface_table, single=False)
        self.interface_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        for column in range(1, 6):
            self.interface_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        self.interface_table.itemSelectionChanged.connect(self._on_interface_selected)
        iface_layout.addWidget(self.interface_table, 1)

        iface_buttons = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh interfaces")
        self.refresh_button.clicked.connect(self._refresh_interfaces)
        self.start_capture_button = QPushButton("Start capture")
        self.start_capture_button.setObjectName("primary")
        self.start_capture_button.clicked.connect(lambda: self._start_capture())
        self.stop_capture_button = QPushButton("Stop capture")
        self.stop_capture_button.clicked.connect(lambda: self._stop_capture())
        iface_buttons.addWidget(self.refresh_button)
        iface_buttons.addWidget(self.start_capture_button)
        iface_buttons.addWidget(self.stop_capture_button)
        iface_buttons.addStretch(1)
        iface_layout.addLayout(iface_buttons)

        self.capture_state_label = QLabel("Capture: stopped")
        self.capture_state_label.setWordWrap(True)
        iface_layout.addWidget(self.capture_state_label)

        self.permission_label = QLabel("Select an interface to evaluate capture readiness.")
        self.permission_label.setObjectName("bannerInfo")
        self.permission_label.setWordWrap(True)
        self.permission_label.setTextFormat(Qt.TextFormat.RichText)
        iface_layout.addWidget(self.permission_label)

        discovery_group = QGroupBox("2 · Identify discovery")
        discovery_group_layout = QVBoxLayout(discovery_group)
        # The group holds many filter fields; without its own scroll area a
        # short window squeezes it below its minimum height and the Discover
        # button and status labels become unreachable.
        discovery_scroll = QScrollArea()
        discovery_scroll.setWidgetResizable(True)
        discovery_scroll.setFrameShape(QFrame.Shape.NoFrame)
        discovery_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        discovery_scroll.setMinimumHeight(150)
        discovery_scroll.setStyleSheet(
            "QScrollArea{background:transparent;border:none;}"
        )
        discovery_content = QWidget()
        discovery_layout = QVBoxLayout(discovery_content)
        discovery_layout.setContentsMargins(0, 0, 0, 0)
        discovery_layout.setSpacing(4)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setVerticalSpacing(4)
        form.setContentsMargins(0, 0, 0, 0)
        # On a narrow pane the labels move above their fields instead of
        # forcing the section wider than the window.
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.5, 60.0)
        self.timeout_spin.setSingleStep(0.5)
        self.timeout_spin.setDecimals(1)
        self.timeout_spin.setSuffix(" s")
        self.timeout_spin.setValue(self.config.timeout_s)
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(1, 6400)
        self.delay_spin.setValue(self.config.response_delay_factor)
        self.delay_spin.setSuffix(" × 10 ms")
        self.vlan_spin = QSpinBox()
        self.vlan_spin.setRange(0, 4094)
        self.vlan_spin.setSpecialValueText("untagged")
        self.vlan_spin.setValue(int(self.config.vlan_id or 0))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(
            "Exact NameOfStation; leave empty for Identify-All"
        )
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.setToolTip(
            "Optional: send an Identify-filter request for this exact NameOfStation "
            "instead of Identify-All."
        )
        self.alias_filter_edit = QLineEdit()
        self.alias_filter_edit.setPlaceholderText("Exact AliasName (optional)")
        self.alias_filter_edit.setClearButtonEnabled(True)
        self.vendor_filter_edit = QLineEdit()
        self.vendor_filter_edit.setPlaceholderText(
            "Exact vendor / type of station (optional)"
        )
        self.vendor_filter_edit.setClearButtonEnabled(True)
        self.vendor_id_filter_edit = QLineEdit()
        self.vendor_id_filter_edit.setPlaceholderText("e.g. 0x002A (with device ID)")
        self.device_id_filter_edit = QLineEdit()
        self.device_id_filter_edit.setPlaceholderText("e.g. 0x0101 (with vendor ID)")
        self.role_filter_spin = QSpinBox()
        self.role_filter_spin.setRange(0, 255)
        self.role_filter_spin.setSpecialValueText("any")
        self.role_filter_spin.setValue(0)
        self.role_filter_spin.setToolTip(
            "Optional Device role filter byte (0x01 IO-Device, 0x02 IO-Controller, …); "
            "0 means any role."
        )
        form.addRow("Timeout", self.timeout_spin)
        form.addRow("ResponseDelayFactor", self.delay_spin)
        form.addRow("VLAN (802.1Q)", self.vlan_spin)
        discovery_layout.addLayout(form)

        # The Identify filter fields are advanced settings; the Edit menu can
        # hide them to save height on small screens. While hidden they are not
        # applied (discovery sends Identify-All), so hidden never means silent.
        self.identify_filter_panel = QWidget()
        filter_form = QFormLayout(self.identify_filter_panel)
        filter_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        filter_form.setVerticalSpacing(4)
        filter_form.setContentsMargins(0, 0, 0, 0)
        filter_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        filter_form.addRow("NameOfStation filter", self.filter_edit)
        filter_form.addRow("Alias filter", self.alias_filter_edit)
        filter_form.addRow("Vendor filter", self.vendor_filter_edit)
        filter_form.addRow("Vendor ID filter", self.vendor_id_filter_edit)
        filter_form.addRow("Device ID filter", self.device_id_filter_edit)
        filter_form.addRow("Device role filter", self.role_filter_spin)
        discovery_layout.addWidget(self.identify_filter_panel)
        rate = QLabel(
            "Pacing: at most one request per "
            f"{self.config.min_request_interval_s:.1f} s. One request per button press; "
            "no automatic retry."
        )
        rate.setWordWrap(True)
        discovery_layout.addWidget(rate)

        buttons = QHBoxLayout()
        self.discover_button = QPushButton("Discover")
        self.discover_button.setObjectName("primary")
        self.discover_button.setToolTip(
            "Send one Identify request: Identify-All, or an Identify filter when any "
            "filter field is filled in."
        )
        self.discover_button.clicked.connect(lambda: self._start_discovery())
        self.cancel_discovery_button = QPushButton("Cancel")
        self.cancel_discovery_button.setEnabled(False)
        self.cancel_discovery_button.clicked.connect(self._cancel_discovery)
        buttons.addWidget(self.discover_button)
        buttons.addWidget(self.cancel_discovery_button)
        buttons.addStretch(1)
        discovery_layout.addLayout(buttons)

        self.discovery_summary_label = QLabel("No discovery run yet.")
        self.discovery_summary_label.setWordWrap(True)
        discovery_layout.addWidget(self.discovery_summary_label)

        self.discovery_warning_label = QLabel("")
        self.discovery_warning_label.setObjectName("bannerWarning")
        self.discovery_warning_label.setWordWrap(True)
        self.discovery_warning_label.setTextFormat(Qt.TextFormat.RichText)
        self.discovery_warning_label.setVisible(False)
        discovery_layout.addWidget(self.discovery_warning_label)
        discovery_layout.addStretch(1)
        discovery_scroll.setWidget(discovery_content)
        discovery_group_layout.addWidget(discovery_scroll, 1)

        top_layout.addWidget(iface_group, 3)
        top_layout.addWidget(discovery_group, 2)

        devices_group = QGroupBox("3 · Discovered devices (select exactly one target)")
        devices_layout = QVBoxLayout(devices_group)
        device_filter_row = QHBoxLayout()
        self.device_search_edit = QLineEdit()
        self.device_search_edit.setPlaceholderText("Filter: name, MAC, IP, vendor…")
        self.device_search_edit.setClearButtonEnabled(True)
        self.device_search_edit.setToolTip(
            "Client-side filter of the discovered device table. It changes nothing on "
            "the wire; use the NameOfStation filter above to filter the Identify request."
        )
        self.device_search_edit.textChanged.connect(self._apply_device_filter)
        self.uncommissioned_check = QCheckBox("Only uncommissioned")
        self.uncommissioned_check.setToolTip(
            "Show only devices that advertise no NameOfStation."
        )
        self.uncommissioned_check.toggled.connect(self._apply_device_filter)
        self.export_inventory_button = QPushButton("Export inventory (CSV)…")
        self.export_inventory_button.setToolTip(
            "Write one CSV row per discovered device (as found)."
        )
        self.export_inventory_button.clicked.connect(self._export_inventory)
        self.compare_plan_button = QPushButton("Compare plan (CSV)…")
        self.compare_plan_button.setToolTip(
            "Compare the discovered devices with a plan CSV and report differences."
        )
        self.compare_plan_button.clicked.connect(self._compare_inventory_plan)
        device_filter_row.addWidget(self.device_search_edit, 1)
        device_filter_row.addWidget(self.uncommissioned_check)
        device_filter_row.addWidget(self.export_inventory_button)
        device_filter_row.addWidget(self.compare_plan_button)
        devices_layout.addLayout(device_filter_row)
        self.device_table = QTableWidget(0, len(DEVICE_COLUMNS))
        self.device_table.setHorizontalHeaderLabels(list(DEVICE_COLUMNS))
        self._configure_table(self.device_table, single=True)
        self.device_table.setSortingEnabled(True)
        # Default view: most recent observation first, as the cache is ordered.
        self.device_table.horizontalHeader().setSortIndicator(
            10, Qt.SortOrder.DescendingOrder
        )
        self.device_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        for index, width in enumerate((140, 170, 120, 120, 120, 90, 90, 150, 190, 150, 190)):
            self.device_table.setColumnWidth(index, width)
        self.device_table.itemSelectionChanged.connect(self._on_device_selected)
        self.device_table.doubleClicked.connect(
            lambda _index: self.tabs.setCurrentWidget(self.device_tab)
        )
        devices_layout.addWidget(self.device_table, 1)
        self.device_count_label = QLabel("0 device(s)")
        devices_layout.addWidget(self.device_count_label)
        splitter.addWidget(top)
        splitter.addWidget(devices_group)
        splitter.setChildrenCollapsible(False)
        splitter.setSizes([640, 240])
        layout.addWidget(splitter, 1)
        return tab

    # ------------------------------------------------------ interface lifecycle
    def _refresh_interfaces(self) -> None:
        if self.transport is not None and self.transport.is_capturing:
            self._stop_capture(silent=True)
        self._suppress_interface_signal = True
        try:
            self.interfaces = enumerate_interfaces(include_mock=True)
            self.interface_table.setRowCount(0)
            for iface in self.interfaces:
                row = self.interface_table.rowCount()
                self.interface_table.insertRow(row)
                self.interface_table.setItem(
                    row, 0, _item(iface.display_name, data=iface)
                )
                self.interface_table.setItem(row, 1, _item(iface.mac or "—", mono=True))
                self.interface_table.setItem(row, 2, _item(iface.addresses_text, mono=True))
                self.interface_table.setItem(row, 3, _item(iface.link_text))
                self.interface_table.setItem(row, 4, _item(iface.kind))
                self.interface_table.setItem(
                    row, 5, _item("mock" if iface.kind == "mock" else "check on select")
                )
            target_id = self.current_interface.id if self.current_interface else None
            target_row = -1
            if target_id:
                for row, iface in enumerate(self.interfaces):
                    if iface.id == target_id:
                        target_row = row
                        break
            if target_row >= 0:
                self.interface_table.selectRow(target_row)
            else:
                self.interface_table.clearSelection()
                self.interface_table.setCurrentCell(-1, -1)
            if self.current_interface is not None and target_row < 0:
                # The previously selected interface disappeared.
                try:
                    if self.transport is not None:
                        self.transport.close()
                except Exception:
                    pass
                self.transport = None
                self.discovery_service = None
                self.get_service = None
                self.write_service = None
                self.request_limiter = None
                self.current_interface = None
                self.last_readiness = None
        finally:
            self._suppress_interface_signal = False
        if self.current_interface is not None:
            self._activate_interface(self.current_interface)
        else:
            self._update_capture_controls()
            self.permission_label.setText(
                "Select one interface explicitly. The Demo (mock) row works without "
                "hardware or privileges; physical NICs should be on the PROFINET segment."
            )
            self.permission_label.setObjectName("bannerInfo")
            self.permission_label.style().unpolish(self.permission_label)
            self.permission_label.style().polish(self.permission_label)
        self.event_log.info(
            "interfaces.refreshed",
            f"{len(self.interfaces)} interface(s) enumerated",
            {"interfaces": [i.name for i in self.interfaces]},
        )

    def _on_interface_selected(self) -> None:
        if self._suppress_interface_signal:
            return
        row = self.interface_table.currentRow()
        if 0 <= row < len(self.interfaces):
            self._activate_interface(self.interfaces[row])

    def _activate_interface(self, iface: InterfaceInfo) -> None:
        if (
            self.current_interface is not None
            and self.current_interface.id == iface.id
            and self.transport is not None
        ):
            return
        if self._monitor_running():
            self._stop_monitor(silent=True)
            worker = self.monitor_worker
            if worker is not None:
                worker.wait(3000)
                worker.deleteLater()
            self.monitor_worker = None
        self.controller.reset_session()
        self.capture.clear()
        self.transaction_table.setRowCount(0)
        self.device_table.setRowCount(0)
        self.device_count_label.setText("0 device(s)")
        self.test_results_table.setRowCount(0)
        self.test_summary_label.setText("No tests run.")
        self.packet_table.setRowCount(0)
        self.packet_detail.clear()
        self.packet_detail_label.setText("Select a frame to inspect it.")
        self.monitor_changes_table.setRowCount(0)
        self.monitor_changes_label.setText("0 change(s) recorded.")
        self.monitor_cycle_label.setText("No cycles completed.")
        self.monitor_state_label.setText("Idle. No monitor run yet.")
        self.monitor_notes_label.setVisible(False)
        self.config_result_label.setText(
            "No configuration operation has been sent in this session."
        )
        self.reset_result_label.setText("No reset operation has been sent in this session.")
        self.reset_post_check_label.setText("")
        self.current_interface = iface
        try:
            self.controller.open_interface(
                router=self.router,
                min_interval_s=self.config.min_request_interval_s,
                event_log=self._service_log,
            )
        except Exception as exc:
            self.event_log.error("interface.activate", f"Could not activate interface: {exc}")
            self.permission_label.setText(
                f"<b>Cannot use this interface.</b><br>{esc(str(exc))}"
            )
            self.permission_label.setObjectName("bannerDanger")
            self.permission_label.style().unpolish(self.permission_label)
            self.permission_label.style().polish(self.permission_label)
        self._update_permission_label()
        self._update_capture_controls()
        self._show_device(None)
        self._update_report_preview()
        self.event_log.info(
            "interface.selected",
            f"Selected {iface.name} ({iface.mac or 'no MAC'})",
            {
                "interface_id": iface.id,
                "kind": iface.kind,
                "mac": iface.mac,
                "addresses": iface.addresses_text,
                "link": iface.link_text,
            },
        )

    def _update_permission_label(self) -> None:
        if self.current_interface is None or self.transport is None:
            self.permission_label.setText("Select an interface to evaluate capture readiness.")
            self.permission_label.setObjectName("bannerInfo")
        elif self.current_interface.kind == "mock":
            self.permission_label.setText(
                "<b>Demo (mock) interface.</b> No privileges, driver, or hardware required. "
                "Three simulated devices respond to Identify. Set/Reset are simulated in "
                "memory for guarded workflow testing; no hardware is affected."
            )
            self.permission_label.setObjectName("bannerOk")
        elif self.last_readiness is not None:
            readiness = self.last_readiness
            hints = "".join(f"<br>• {esc(h)}" for h in readiness.hints)
            if readiness.ready:
                self.permission_label.setText(
                    f"<b>Ready.</b> {esc(readiness.message)}"
                )
                self.permission_label.setObjectName("bannerOk")
            else:
                self.permission_label.setText(
                    f"<b>Capture may fail.</b> {esc(readiness.message)}"
                    f"<br><b>Remedies:</b>{hints}"
                )
                self.permission_label.setObjectName("bannerDanger")
        self.permission_label.style().unpolish(self.permission_label)
        self.permission_label.style().polish(self.permission_label)
        self.status_privileges.setText(
            f"Privileges: {'ready' if self.last_readiness and self.last_readiness.ready else 'check'}"
        )

    # -------------------------------------------------------------- discovery
    def _refresh_discover_tooltip(self) -> None:
        """Keep the Discover tooltip truthful about hidden filter fields."""
        if self.config.show_identify_filters:
            self.discover_button.setToolTip(
                "Send one Identify request: Identify-All, or an Identify filter when any "
                "filter field is filled in."
            )
        else:
            self.discover_button.setToolTip(
                "Send one Identify-All request. The Identify filter fields are hidden "
                "(Edit menu), so they are not applied."
            )

    @staticmethod
    def _filter_id(value: str, label: str) -> int | None:
        text = value.strip()
        if not text:
            return None
        try:
            parsed = int(text, 0)
        except ValueError as exc:
            raise ValueError(f"{label} must be a value such as 0x002A") from exc
        if not 0 <= parsed <= 0xFFFF:
            raise ValueError(f"{label} must be 0..0xFFFF")
        return parsed

    def _start_discovery(
        self, unicast_mac: str | None = None, *, apply_filter: bool = True
    ) -> None:
        if self._closing:
            return
        if self._discovery_running():
            return
        if (
            self._tests_running()
            or self._get_running()
            or self._write_running()
            or self._post_check_running()
            or self._monitor_running()
        ):
            QMessageBox.information(
                self,
                "Another operation is running",
                "Wait for the current Get, test, configuration, or reset operation to finish "
                "(or cancel it) before starting discovery.",
            )
            return
        if self.transport is None or self.discovery_service is None:
            QMessageBox.warning(self, "No interface", "Select an interface first.")
            return
        filter_name: str | None = None
        identify_filter = None
        if (
            unicast_mac is None
            and apply_filter
            and self.config.show_identify_filters
        ):
            candidate = self.filter_edit.text().strip()
            if candidate:
                report = validate_station_name(candidate)
                if not report.ok:
                    QMessageBox.warning(
                        self, "Invalid NameOfStation filter", report.summary()
                    )
                    return
                filter_name = candidate
            try:
                vendor_id = self._filter_id(
                    self.vendor_id_filter_edit.text(), "Vendor ID"
                )
                device_id = self._filter_id(
                    self.device_id_filter_edit.text(), "Device ID"
                )
            except ValueError as exc:
                QMessageBox.warning(self, "Invalid Identify filter", str(exc))
                return
            if (vendor_id is None) != (device_id is None):
                QMessageBox.warning(
                    self,
                    "Invalid Identify filter",
                    "Enter both a Vendor ID and a Device ID, or neither.",
                )
                return
            identify_filter = IdentifyFilter(
                name_of_station=filter_name,
                alias=self.alias_filter_edit.text().strip() or None,
                vendor_name=self.vendor_filter_edit.text().strip() or None,
                vendor_id=vendor_id,
                device_id=device_id,
                device_role=int(self.role_filter_spin.value()) or None,
            )
            if identify_filter.is_empty():
                identify_filter = None
            else:
                try:
                    identify_filter.encode()
                except Exception as exc:
                    QMessageBox.warning(
                        self, "Invalid Identify filter", str(exc)
                    )
                    return
        if not self.transport.is_capturing and not self._start_capture():
            return
        cfg = DiscoveryConfig(
            timeout_s=self.timeout_spin.value(),
            response_delay_factor=self.delay_spin.value(),
            vlan_id=self.vlan_spin.value() or None,
            unicast_mac=unicast_mac,
            min_request_interval_s=self.config.min_request_interval_s,
            identify_filter_name=filter_name,
            identify_filter=identify_filter,
        )
        self.discovery_cancel = threading.Event()
        worker = DiscoveryWorker(self.controller, cfg, self.discovery_cancel, parent=self)
        worker.finished_ok.connect(self._on_discovery_finished)
        worker.failed.connect(self._on_discovery_failed)
        worker.progress.connect(self._on_discovery_progress)
        worker.finished.connect(self._on_discovery_thread_finished)
        self.discovery_worker = worker
        if unicast_mac:
            self.discovery_summary_label.setText(f"Unicast Identify to {unicast_mac}…")
        elif identify_filter is not None:
            self.discovery_summary_label.setText(
                f"Discovering ({identify_filter.summary})…"
            )
        elif filter_name:
            self.discovery_summary_label.setText(
                f"Discovering NameOfStation {filter_name!r}…"
            )
        else:
            self.discovery_summary_label.setText("Discovering…")
        self.discovery_warning_label.setVisible(False)
        mode = (
            f"unicast {unicast_mac}"
            if unicast_mac
            else (
                f"filters {identify_filter.summary}"
                if identify_filter is not None
                else (f"NameOfStation filter {filter_name!r}" if filter_name else "multicast")
            )
        )
        self.event_log.info(
            "discovery.start",
            f"Identify request ({mode})",
            {
                "interface": self.current_interface.id if self.current_interface else None,
                "timeout_s": cfg.timeout_s,
                "response_delay_factor": cfg.response_delay_factor,
                "vlan_id": cfg.vlan_id,
                "unicast_mac": unicast_mac,
                "identify_filter_name": filter_name,
                "identify_filter": (
                    identify_filter.summary if identify_filter is not None else None
                ),
            },
        )
        self._update_capture_controls()
        self.discover_button.setEnabled(False)
        self.cancel_discovery_button.setEnabled(True)
        worker.start()

    def _cancel_discovery(self) -> None:
        self.discovery_cancel.set()
        self.discovery_summary_label.setText("Cancelling discovery…")
        self.event_log.warning("discovery.cancel", "Cancellation requested by user")

    def _on_discovery_progress(self, message: str) -> None:
        self.discovery_summary_label.setText(message)

    def _on_discovery_finished(self, result: DiscoveryResult) -> None:
        self.latest_discovery = result
        self.discovery_runs.append(result)
        if len(self.discovery_runs) > 50:
            self.discovery_runs = self.discovery_runs[-50:]
        self._ingest_result(result)
        self._populate_device_table()
        self._append_transaction_rows(result.transactions)
        self.discovery_summary_label.setText(
            f"{result.outcome_text} · {len(result.devices)} device(s) · "
            f"{result.duration_ms:.0f} ms · Xid 0x{result.xid:08x} · "
            f"duplicates {result.duplicate_responses} · late {result.late_responses} · "
            f"unmatched {result.unmatched_responses}"
        )
        warnings = list(result.warnings)
        if warnings:
            self.discovery_warning_label.setText(
                "<b>Discovery notes</b><br>"
                + "<br>".join(f"• {esc(w)}" for w in warnings)
            )
            self.discovery_warning_label.setVisible(True)
            for warning in warnings:
                self.event_log.warning("discovery.warning", warning, {"xid": result.xid})
        else:
            self.discovery_warning_label.setVisible(False)
        self._update_report_preview()
        self._update_capture_stats()
        self._update_capture_controls()
        # The Test Runner offers the discovered devices as devices under test.
        self._refresh_dut_combo()

    def _on_discovery_failed(self, message: str) -> None:
        self.discovery_summary_label.setText("Discovery failed.")
        self.event_log.error("discovery.failed", message)
        QMessageBox.critical(self, "Discovery failed", message)
        self._update_capture_controls()

    def _on_discovery_thread_finished(self) -> None:
        if self.discovery_worker is not None:
            self.discovery_worker.deleteLater()
        self.discovery_worker = None
        self._update_capture_controls()

    # ------------------------------------------------- device table filtering
    def _apply_device_filter(self) -> None:
        """Apply the client-side text/uncommissioned filter to the device table."""
        query = self.device_search_edit.text()
        only_uncommissioned = self.uncommissioned_check.isChecked()
        visible = 0
        for row in range(self.device_table.rowCount()):
            item = self.device_table.item(row, 0)
            device = item.data(Qt.ItemDataRole.UserRole) if item else None
            show = isinstance(device, DeviceIdentity) and device_matches_filter(
                device, query, uncommissioned_only=only_uncommissioned
            )
            self.device_table.setRowHidden(row, not show)
            if show:
                visible += 1
        total = self.device_table.rowCount()
        latest = len(self.latest_discovery.devices) if self.latest_discovery else 0
        self.device_count_label.setText(
            f"{visible} of {total} shown · {latest} in latest run"
        )

    # ------------------------------------------------- inventory and planning
    def _export_inventory(self) -> None:
        devices = self._devices_for_current_interface()
        if not devices:
            QMessageBox.information(
                self,
                "No devices",
                "Run discovery first; there is nothing to export.",
            )
            return
        default_path = Path(self.config.report_directory) / (
            f"inventory-{time.strftime('%Y%m%d-%H%M%S')}.csv"
        )
        path, _selected = QFileDialog.getSaveFileName(
            self,
            "Export device inventory",
            str(default_path),
            "CSV files (*.csv);;All files (*)",
        )
        if not path:
            return
        try:
            Path(path).write_text(inventory_csv(devices), encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Inventory export failed", str(exc))
            return
        self.event_log.info(
            "inventory.exported",
            f"Inventory written to {path}",
            {"path": path, "devices": len(devices)},
        )
        QMessageBox.information(
            self,
            "Inventory exported",
            f"{len(devices)} device(s) written to\n{path}",
        )

    def _compare_inventory_plan(self) -> None:
        devices = self._devices_for_current_interface()
        if not devices:
            QMessageBox.information(
                self,
                "No devices",
                "Run discovery first; there is nothing to compare.",
            )
            return
        path, _selected = QFileDialog.getOpenFileName(
            self,
            "Select plan CSV",
            self.config.report_directory,
            "CSV files (*.csv);;All files (*)",
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Could not read plan", str(exc))
            return
        entries, warnings = parse_plan_csv(text)
        findings = compare_plan(devices, entries)
        for warning in warnings:
            self.event_log.warning(
                "inventory.plan_warning", warning, {"path": path}
            )
        for finding in findings:
            self.event_log.warning(
                "inventory.plan_finding",
                finding.detail,
                {**finding.to_dict(), "path": path},
            )
        if findings:
            shown = "\n".join(f"• {finding.detail}" for finding in findings[:20])
            if len(findings) > 20:
                shown += f"\n… and {len(findings) - 20} more (see the event log)."
            QMessageBox.warning(
                self, f"Plan check: {len(findings)} finding(s)", shown
            )
        else:
            QMessageBox.information(
                self,
                "Plan check",
                "No differences between the plan and the discovered devices.",
            )
