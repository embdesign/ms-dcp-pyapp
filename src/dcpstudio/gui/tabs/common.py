"""Shared constants and Qt helpers for the tab builders.

Tab construction lives in the sibling modules so ``main_window.py`` stays a
controller (state, services, worker lifecycle). These helpers are pure Qt
formatting; none of them touch the network or the safety gate.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel, QTableWidgetItem

from ..presentation import display_addr

DEVICE_COLUMNS = (
    "MAC address",
    "NameOfStation",
    "IP address",
    "Subnet mask",
    "Gateway",
    "Vendor ID",
    "Device ID",
    "Role",
    "DCP options",
    "Interface",
    "Last seen (UTC)",
)

PACKET_COLUMNS = (
    "Time (UTC)",
    "Dir",
    "Kind",
    "FrameID",
    "Service",
    "Type",
    "Source",
    "Destination",
    "Summary",
    "Bytes",
)

MAX_PACKET_ROWS = 1500
MAX_LOG_ROWS = 2500

# Sentinel for the legacy FactoryReset (05/05), which carries no reset-mode
# number. Kept as a string so it cannot collide with an integer mode value.
LEGACY_RESET_CHOICE = "legacy"


def banner(text: str, kind: str = "Warning") -> QLabel:
    label = QLabel(text)
    label.setObjectName(f"banner{kind}")
    label.setWordWrap(True)
    label.setTextFormat(Qt.TextFormat.RichText)
    return label


def mono_font() -> QFont:
    font = QFont("DejaVu Sans Mono")
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSize(10)
    return font


def display_addr_text(value: str | None) -> str:
    return display_addr(value)


def table_item(text: str, *, mono: bool = False, data: object | None = None) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if mono:
        item.setFont(mono_font())
    if data is not None:
        item.setData(Qt.ItemDataRole.UserRole, data)
    return item
