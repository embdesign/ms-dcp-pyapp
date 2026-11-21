"""Configuration tab construction."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from .common import banner, scrollable


class ConfigurationTabMixin:
    def _build_config_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        layout.addWidget(
            banner(
                "<b>Confirmed configuration.</b> Every Set frame is preceded by a "
                "confirmation dialog and a fresh unicast Identify revalidation. Name/IP "
                "changes can interrupt communication and may require a controller "
                "reconnect. Use an isolated lab.",
                "Warning",
            )
        )

        target_group = QGroupBox("Selected target")
        target_layout = QGridLayout(target_group)
        self.config_target_label = QLabel(
            "No device selected. Discover and select exactly one target first."
        )
        self.config_target_label.setWordWrap(True)
        self.config_target_label.setTextFormat(Qt.TextFormat.RichText)
        target_layout.addWidget(self.config_target_label, 0, 0, 1, 2)
        layout.addWidget(target_group)

        name_group = QGroupBox("NameOfStation")
        name_layout = QVBoxLayout(name_group)
        name_row = QHBoxLayout()
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. line-01.conveyor")
        self.validate_name_button = QPushButton("Validate name")
        self.validate_name_button.clicked.connect(self._validate_name)
        name_row.addWidget(self.name_edit, 1)
        name_row.addWidget(self.validate_name_button)
        name_layout.addLayout(name_row)
        self.name_validation_label = QLabel("")
        self.name_validation_label.setWordWrap(True)
        name_layout.addWidget(self.name_validation_label)
        name_persistence = QHBoxLayout()
        self.temp_radio = QRadioButton("Temporary (BlockQualifier 0x0000)")
        self.perm_radio = QRadioButton("Permanent (BlockQualifier 0x0001)")
        self.temp_radio.setChecked(True)
        name_persistence.addWidget(self.temp_radio)
        name_persistence.addWidget(self.perm_radio)
        name_persistence.addStretch(1)
        self.apply_name_button = QPushButton("Set NameOfStation…")
        self.apply_name_button.setObjectName("danger")
        self.apply_name_button.setEnabled(False)
        self.apply_name_button.clicked.connect(self._apply_name)
        name_persistence.addWidget(self.apply_name_button)
        name_layout.addLayout(name_persistence)
        rules = QLabel(
            "Rules: 0–240 characters (empty clears the name), lowercase labels separated by "
            "'.', each 1–63 chars of a–z, 0–9 and '-'; no leading/trailing '-'; first label "
            "must not be reserved 'port-xyz'; name must not look like an IPv4 address."
        )
        rules.setWordWrap(True)
        rules.setStyleSheet("color: #64748b;")
        name_layout.addWidget(rules)
        layout.addWidget(name_group)

        ip_group = QGroupBox("IPv4 parameters")
        ip_layout = QVBoxLayout(ip_group)
        grid = QGridLayout()
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("192.168.1.10")
        self.mask_edit = QLineEdit()
        self.mask_edit.setPlaceholderText("255.255.255.0")
        self.gateway_edit = QLineEdit()
        self.gateway_edit.setPlaceholderText("192.168.1.1 (optional)")
        grid.addWidget(QLabel("IP address"), 0, 0)
        grid.addWidget(self.ip_edit, 0, 1)
        grid.addWidget(QLabel("Subnet mask"), 1, 0)
        grid.addWidget(self.mask_edit, 1, 1)
        grid.addWidget(QLabel("Gateway"), 2, 0)
        grid.addWidget(self.gateway_edit, 2, 1)
        self.dns_edit = QLineEdit()
        self.dns_edit.setPlaceholderText("192.168.1.53, 192.168.1.54 (optional, max 4)")
        grid.addWidget(QLabel("DNS servers"), 3, 0)
        grid.addWidget(self.dns_edit, 3, 1)
        self.validate_ip_button = QPushButton("Validate IP suite")
        self.validate_ip_button.clicked.connect(self._validate_ip)
        grid.addWidget(self.validate_ip_button, 4, 1, 1, 1, Qt.AlignmentFlag.AlignLeft)
        ip_layout.addLayout(grid)
        self.ip_validation_label = QLabel("")
        self.ip_validation_label.setWordWrap(True)
        ip_layout.addWidget(self.ip_validation_label)
        ip_persistence = QHBoxLayout()
        self.ip_temp_radio = QRadioButton("Temporary (BlockQualifier 0x0000)")
        self.ip_perm_radio = QRadioButton("Permanent (BlockQualifier 0x0001)")
        self.ip_temp_radio.setChecked(True)
        ip_persistence.addWidget(self.ip_temp_radio)
        ip_persistence.addWidget(self.ip_perm_radio)
        ip_persistence.addStretch(1)
        self.apply_ip_button = QPushButton("Set IP parameters…")
        self.apply_ip_button.setObjectName("danger")
        self.apply_ip_button.setEnabled(False)
        self.apply_ip_button.clicked.connect(self._apply_ip)
        ip_persistence.addWidget(self.apply_ip_button)
        self.apply_ip_suite_button = QPushButton("Set full IP suite…")
        self.apply_ip_suite_button.setObjectName("danger")
        self.apply_ip_suite_button.setEnabled(False)
        self.apply_ip_suite_button.setToolTip(
            "Set IP, mask, gateway and the DNS server list in one guarded 01/03 block."
        )
        self.apply_ip_suite_button.clicked.connect(self._apply_ip_suite)
        ip_persistence.addWidget(self.apply_ip_suite_button)
        ip_layout.addLayout(ip_persistence)
        ip_note = QLabel(
            "Discovery does not prove that an IP address is unused. Temporary means the "
            "value is active but not stored by a conformant stack; permanent requests "
            "non-volatile storage. A Set acknowledgement is followed by one read-only Get "
            "for independent verification, with no automatic retry."
        )
        ip_note.setWordWrap(True)
        ip_note.setStyleSheet("color: #64748b;")
        ip_layout.addWidget(ip_note)
        layout.addWidget(ip_group)

        dhcp_group = QGroupBox("DHCP")
        dhcp_layout = QVBoxLayout(dhcp_group)
        dhcp_row = QHBoxLayout()
        self.dhcp_combo = QComboBox()
        self.dhcp_combo.addItem("Do not use DHCP (default)", 0)
        self.dhcp_combo.addItem("Do not use DHCP; reset all DHCP options", 1)
        self.dhcp_combo.addItem("Use DHCP for address resolution", 2)
        self.apply_dhcp_button = QPushButton("Set DHCP control…")
        self.apply_dhcp_button.setObjectName("danger")
        self.apply_dhcp_button.setEnabled(False)
        self.apply_dhcp_button.clicked.connect(self._apply_dhcp)
        dhcp_row.addWidget(self.dhcp_combo, 1)
        dhcp_row.addWidget(self.apply_dhcp_button)
        dhcp_layout.addLayout(dhcp_row)
        dhcp_note = QLabel(
            "Enabling DHCP may replace the current IP address; disabling it can drop or "
            "keep the address depending on the device. The acknowledgement is followed "
            "by one read-only Get; device support varies."
        )
        dhcp_note.setWordWrap(True)
        dhcp_note.setStyleSheet("color: #64748b;")
        dhcp_layout.addWidget(dhcp_note)
        layout.addWidget(dhcp_group)

        self.config_result_label = QLabel(
            "No configuration operation has been sent in this session."
        )
        self.config_result_label.setWordWrap(True)
        self.config_result_label.setTextFormat(Qt.TextFormat.RichText)
        config_actions = QHBoxLayout()
        self.cancel_config_write_button = QPushButton("Cancel configuration operation")
        self.cancel_config_write_button.setEnabled(False)
        self.cancel_config_write_button.clicked.connect(self._cancel_write)
        config_actions.addWidget(self.cancel_config_write_button)
        config_actions.addStretch(1)
        layout.addLayout(config_actions)
        layout.addWidget(self.config_result_label)
        layout.addStretch(1)
        return scrollable(tab)
