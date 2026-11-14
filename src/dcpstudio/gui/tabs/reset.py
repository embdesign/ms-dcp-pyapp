"""Reset tab construction and reset-mode description."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from ...codec import request_qualifier
from ...constants import RESET_MODES, SUPPORTED_RESET_MODES
from .common import LEGACY_RESET_CHOICE, banner, table_item


class ResetTabMixin:
    def _build_reset_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        layout.addWidget(
            banner(
                "<b>Guarded reset.</b> ResetToFactorySettings uses DCP option 05 / "
                "sub-option 06 with BlockQualifier = mode &lt;&lt; 1. Device support and the "
                "data actually erased are vendor-dependent. Every reset requires configuration "
                "mode, per-operation authorization and safe-maintenance confirmation, and "
                "target revalidation. No automatic retry or rollback exists.",
                "Danger",
            )
        )

        target_group = QGroupBox("Selected target")
        target_layout = QVBoxLayout(target_group)
        self.reset_target_label = QLabel(
            "No device selected. Discover and select exactly one target first."
        )
        self.reset_target_label.setWordWrap(True)
        self.reset_target_label.setTextFormat(Qt.TextFormat.RichText)
        target_layout.addWidget(self.reset_target_label)
        layout.addWidget(target_group)

        mode_group = QGroupBox("Reset variant")
        mode_layout = QVBoxLayout(mode_group)
        mode_row = QHBoxLayout()
        self.reset_mode_combo = QComboBox()
        for mode in sorted(SUPPORTED_RESET_MODES):
            meaning = RESET_MODES.get(mode, "Unknown mode")
            self.reset_mode_combo.addItem(
                f"Mode {mode} — {meaning} "
                f"(qualifier 0x{request_qualifier('reset', reset_mode=mode):04x})",
                mode,
            )
        index = self.reset_mode_combo.findData(8)
        if index >= 0:
            self.reset_mode_combo.setCurrentIndex(index)
        self.reset_mode_combo.addItem(
            "Legacy FactoryReset — 05/05 (full reset, no mode field)",
            LEGACY_RESET_CHOICE,
        )
        self.reset_mode_combo.currentIndexChanged.connect(self._update_reset_mode)
        mode_row.addWidget(self.reset_mode_combo, 1)
        mode_layout.addLayout(mode_row)
        self.reset_mode_description = QLabel("")
        self.reset_mode_description.setWordWrap(True)
        mode_layout.addWidget(self.reset_mode_description)
        layout.addWidget(mode_group)

        table = QTableWidget(len(RESET_MODES) + 1, 4)
        table.setHorizontalHeaderLabels(
            ["Reset mode", "Wire BlockQualifier", "Documented meaning", "Status"]
        )
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        for row, (mode, meaning) in enumerate(sorted(RESET_MODES.items())):
            table.setItem(row, 0, table_item(str(mode), mono=True))
            table.setItem(
                row,
                1,
                table_item(f"0x{request_qualifier('reset', reset_mode=mode):04x}", mono=True),
            )
            table.setItem(row, 2, table_item(meaning))
            table.setItem(
                row,
                3,
                table_item(
                    "Implemented (guarded)"
                    if mode in SUPPORTED_RESET_MODES
                    else "Disabled — semantics unverified"
                ),
            )
        legacy_row = len(RESET_MODES)
        table.setItem(legacy_row, 0, table_item("— (05/05)", mono=True))
        table.setItem(legacy_row, 1, table_item("0x0000", mono=True))
        table.setItem(legacy_row, 2, table_item("Legacy FactoryReset — full reset, no mode field"))
        table.setItem(legacy_row, 3, table_item("Implemented (guarded)"))
        layout.addWidget(table, 1)

        controls = QHBoxLayout()
        self.apply_reset_button = QPushButton("Execute reset…")
        self.apply_reset_button.setObjectName("danger")
        self.apply_reset_button.setEnabled(False)
        self.apply_reset_button.clicked.connect(self._apply_reset)
        self.cancel_reset_button = QPushButton("Cancel")
        self.cancel_reset_button.setEnabled(False)
        self.cancel_reset_button.clicked.connect(self._cancel_reset_operation)
        self.reset_post_check_button = QPushButton("Verify target after reset (read-only)")
        self.reset_post_check_button.setEnabled(False)
        self.reset_post_check_button.setToolTip(
            "Sends one unicast Identify. A response proves reachability only; inspect the "
            "current name/IP independently."
        )
        self.reset_post_check_button.clicked.connect(self._start_post_check)
        controls.addWidget(self.apply_reset_button)
        controls.addWidget(self.cancel_reset_button)
        controls.addWidget(self.reset_post_check_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.reset_result_label = QLabel("No reset operation has been sent in this session.")
        self.reset_result_label.setWordWrap(True)
        self.reset_result_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self.reset_result_label)
        self.reset_post_check_label = QLabel("")
        self.reset_post_check_label.setWordWrap(True)
        self.reset_post_check_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self.reset_post_check_label)

        notes = QLabel(
            "<b>Legacy 05/05:</b> an older FactoryReset with no mode field. It is sent with "
            "BlockQualifier 0x0000 and performs a full reset (p-net sets reset mode 99, "
            "\"reset all\"); the erased scope cannot be selected. <b>Unknown semantics:</b> "
            "engineering reset (mode 3) and 'reset and restore' (mode 9) are listed by "
            "Wireshark but were not verified on hardware, so they are not transmitted. A DCP "
            "factory reset does not necessarily erase application data, firmware, or "
            "vendor-specific settings."
        )
        notes.setWordWrap(True)
        notes.setTextFormat(Qt.TextFormat.RichText)
        notes.setStyleSheet("color: #475569;")
        layout.addWidget(notes)
        self._update_reset_mode()
        return tab

    def _update_reset_mode(self, *_args) -> None:
        mode = self.reset_mode_combo.currentData()
        if mode is None:
            self.reset_mode_description.setText("")
            return
        if mode == LEGACY_RESET_CHOICE:
            self.reset_mode_description.setText(
                "<b>Option 05 / sub-option 05</b> · BlockQualifier 0x0000 (\"Default\"). "
                "This older variant has no mode field: the device performs a full reset and "
                "p-net ignores the qualifier. The erased scope is vendor-dependent and cannot "
                "be selected. Device support is not guaranteed."
            )
            return
        mode = int(mode)
        meaning = RESET_MODES.get(mode, "Unknown mode")
        scope = {
            1: "Resets application data; communication parameters may remain.",
            2: "Resets communication parameters (name/IP); application data may remain.",
            4: "Resets all stored data except the security configuration.",
            8: "Reset all stored data to factory values; vendor-dependent scope.",
        }.get(mode, "Documented scope is incomplete.")
        self.reset_mode_description.setText(
            f"<b>Qualifier 0x{request_qualifier('reset', reset_mode=mode):04x}</b> · "
            f"{html.escape(meaning)}. "
            f"{html.escape(scope)} Device support is not guaranteed."
        )
