"""Shared constants and Qt helpers for the tab builders.

Tab construction lives in the sibling modules so ``main_window.py`` stays a
controller (state, services, worker lifecycle). These helpers are pure Qt
formatting; none of them touch the network or the safety gate.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QScrollArea,
    QTableWidgetItem,
    QWidget,
)

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


def scrollable(content: QWidget) -> QScrollArea:
    """Wrap a form page so its fields keep their natural height.

    A tab page that is one plain column makes Qt shrink every widget when the
    window gets shorter than the layout's minimum size hint; line edits then
    collapse below their text height and become unreadable. Inside a
    ``widgetResizable`` scroll area the page keeps its ``minimumSizeHint`` and
    the viewport scrolls instead. Use this for label/field pages; pages whose
    main widget is a table or splitter scroll on their own.
    """
    area = QScrollArea()
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setWidgetResizable(True)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setWidget(content)
    return area


def mono_font() -> QFont:
    font = QFont("DejaVu Sans Mono")
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSize(10)
    return font


# Families used for aligned text. DejaVu ships with Linux, the others cover
# Windows; the generic family is only a last resort.
MONO_FAMILIES_CSS = (
    '"DejaVu Sans Mono", "Liberation Mono", "Noto Sans Mono", '
    '"Cascadia Mono", "Consolas", monospace'
)
MONO_FONT_SIZE_PX = 12


def apply_mono_font(widget: QWidget) -> None:
    """Give a read-only text widget a real monospace face.

    ``MainWindow``'s style sheet sets a proportional ``font-family`` on every
    ``QWidget``, and a style sheet always wins over :meth:`QWidget.setFont`.
    Only a rule set on the widget itself can override that, so hex dumps and
    other column-aligned text stay fixed-width. The rule sets the family and
    size only; colours, border and padding still come from the window sheet.
    """
    widget.setFont(mono_font())
    widget.setStyleSheet(
        f"font-family: {MONO_FAMILIES_CSS}; font-size: {MONO_FONT_SIZE_PX}px;"
    )


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
