"""One Qt-free path for HTML escaping and table markup.

Both renderers — the written report (`reporting.py`) and the widget summaries
(`gui/presentation.py`) — used to call ``html.escape`` directly and hand-write
``<tr>/<td>`` markup. The escaping policy and the empty-row/list markup therefore
existed dozens of times. This module owns them.

Pure module: no I/O, no Qt, no models.
"""

from __future__ import annotations

import html
from collections.abc import Iterable


def esc(value: object) -> str:
    """Escape a value for HTML text and quoted attributes."""
    return html.escape(str(value), quote=True)


def cell(value: object, *, mono: bool = False) -> str:
    """One table body cell."""
    text = esc(value)
    return f"<td class='mono'>{text}</td>" if mono else f"<td>{text}</td>"


def row(*cells: str, class_name: str | None = None) -> str:
    """One table body row from already-rendered cells."""
    attribute = f" class='{esc(class_name)}'" if class_name else ""
    return f"<tr{attribute}>" + "".join(cells) + "</tr>"


def empty_row(colspan: int, message: str) -> str:
    """The placeholder row shown when a table has no data."""
    return f'<tr><td colspan="{colspan}" class="empty">{esc(message)}</td></tr>'


def li_items(values: Iterable[object]) -> str:
    """A sequence of ``<li>`` elements."""
    return "".join(f"<li>{esc(value)}</li>" for value in values)


def joined(values: Iterable[object], separator: str = "; ") -> str:
    """Escaped values joined into one inline sentence."""
    return separator.join(esc(value) for value in values)
