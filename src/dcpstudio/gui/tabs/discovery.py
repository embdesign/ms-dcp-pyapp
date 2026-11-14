"""Interfaces & Discovery tab construction."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from .common import DEVICE_COLUMNS, banner


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

        discovery_group = QGroupBox("2 · Identify discovery")
        discovery_layout = QVBoxLayout(discovery_group)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
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
        form.addRow("Timeout", self.timeout_spin)
        form.addRow("ResponseDelayFactor", self.delay_spin)
        form.addRow("VLAN (802.1Q)", self.vlan_spin)
        form.addRow("NameOfStation filter", self.filter_edit)
        discovery_layout.addLayout(form)
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
            "Send one Identify request: Identify-All, or a NameOfStation filter when filled in."
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

        self.permission_label = QLabel("Select an interface to evaluate capture readiness.")
        self.permission_label.setObjectName("bannerInfo")
        self.permission_label.setWordWrap(True)
        self.permission_label.setTextFormat(Qt.TextFormat.RichText)
        discovery_layout.addWidget(self.permission_label)

        self.discovery_warning_label = QLabel("")
        self.discovery_warning_label.setObjectName("bannerWarning")
        self.discovery_warning_label.setWordWrap(True)
        self.discovery_warning_label.setTextFormat(Qt.TextFormat.RichText)
        self.discovery_warning_label.setVisible(False)
        discovery_layout.addWidget(self.discovery_warning_label)
        discovery_layout.addStretch(1)

        top_layout.addWidget(iface_group, 3)
        top_layout.addWidget(discovery_group, 2)

        devices_group = QGroupBox("3 · Discovered devices (select exactly one target)")
        devices_layout = QVBoxLayout(devices_group)
        self.device_table = QTableWidget(0, len(DEVICE_COLUMNS))
        self.device_table.setHorizontalHeaderLabels(list(DEVICE_COLUMNS))
        self._configure_table(self.device_table, single=True)
        self.device_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        for index, width in enumerate((140, 170, 120, 120, 120, 90, 90, 150, 190, 150, 190)):
            self.device_table.setColumnWidth(index, width)
        self.device_table.itemSelectionChanged.connect(self._on_device_selected)
        self.device_table.doubleClicked.connect(lambda _index: self.tabs.setCurrentIndex(1))
        devices_layout.addWidget(self.device_table, 1)
        self.device_count_label = QLabel("0 device(s)")
        devices_layout.addWidget(self.device_count_label)

        splitter.addWidget(top)
        splitter.addWidget(devices_group)
        splitter.setSizes([430, 330])
        layout.addWidget(splitter, 1)
        return tab
