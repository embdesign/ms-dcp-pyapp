"""Tests for the shared HTML primitives."""

from __future__ import annotations

from dcpstudio.html_render import cell, empty_row, esc, joined, li_items, row


def test_esc_escapes_text_and_quotes():
    assert esc("<a & b>") == "&lt;a &amp; b&gt;"
    assert esc('say "hi"') == "say &quot;hi&quot;"
    assert esc("it's") == "it&#x27;s"
    assert esc(None) == "None"
    assert esc(3) == "3"


def test_cell_renders_plain_and_mono_cells():
    assert cell("x") == "<td>x</td>"
    assert cell("<x>", mono=True) == "<td class='mono'>&lt;x&gt;</td>"
    assert cell(12) == "<td>12</td>"


def test_row_joins_cells_and_escapes_the_class():
    assert row(cell("a"), cell("b")) == "<tr><td>a</td><td>b</td></tr>"
    assert row(cell("a"), class_name="status-passed") == (
        "<tr class='status-passed'><td>a</td></tr>"
    )
    assert row(cell("a"), class_name="x'y") == "<tr class='x&#x27;y'><td>a</td></tr>"


def test_empty_row_is_the_documented_placeholder():
    assert empty_row(3, "No devices.") == (
        '<tr><td colspan="3" class="empty">No devices.</td></tr>'
    )


def test_li_items_and_joined_escape_each_value():
    assert li_items(["a", "<b>"]) == "<li>a</li><li>&lt;b&gt;</li>"
    assert joined(["a", "<b>"]) == "a; &lt;b&gt;"
    assert joined(["a", "b"], separator=" · ") == "a · b"
