"""Pure HTML/text rendering for the Qt UI.

These helpers turn model objects into the strings the window displays. They do
not touch widgets, signals or I/O, so they can be unit-tested without a
``QApplication`` and reused by any front end.

The window methods ``MainWindow._get_result_html`` etc. delegate here; behaviour
is unchanged.
"""

from __future__ import annotations

import html
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ..model import DeviceIdentity, GetResult, WriteResult, iso_utc
from ..services.get import selector_name

_COLOR_OK = "#155c38"
_COLOR_WARN = "#744800"
_COLOR_ERROR = "#8c1d12"
_COLOR_MUTED = "#64748b"


def display_addr(value: str | None) -> str:
    """Render an optional address, using an em dash for 'not set'."""
    if not value or value == "0.0.0.0":
        return "—"
    return value


def get_result_html(result: GetResult) -> str:
    """One-line summary of a read-only Get transaction."""
    if result.state == "response_received" and not result.block_errors:
        color = _COLOR_OK
    elif result.state in ("response_received", "late_response"):
        color = _COLOR_WARN
    else:
        color = _COLOR_ERROR
    blocks = ", ".join(
        html.escape(selector_name((b.option, b.suboption))) for b in result.blocks
    )
    parts = [
        f"<span style='color:{color}'><b>{html.escape(result.outcome_text)}</b></span>"
        f" · target <code>{html.escape(result.target_mac)}</code>"
        f" · Xid <code>0x{result.xid:08x}</code>"
    ]
    if result.rtt_ms is not None:
        parts.append(f" · RTT {result.rtt_ms:.3f} ms")
    if blocks:
        parts.append(f"<br><b>Blocks received:</b> {blocks}")
    if result.block_errors:
        parts.append(
            f"<br><span style='color:{_COLOR_ERROR}'><b>Block errors:</b> "
            f"{html.escape(result.block_error_text)}</span>"
        )
    if result.warnings:
        parts.append(
            "<br><b>Notes:</b> " + "; ".join(html.escape(w) for w in result.warnings)
        )
    return "".join(parts)


def signal_result_html(result: WriteResult) -> str:
    """Compact result line for the unguarded Signal (LED flash) action.

    Signal stores nothing and has no read-back, so the guarded-write wording
    ("independent verification", block qualifier, Xid, transaction ids) answers
    questions nobody asks here: the operator standing at the device *is* the
    verification. This shows only what the operator cannot see for themselves —
    whether a frame left the NIC and whether the device accepted it. The full
    record stays in the event log and the report.
    """
    if result.state == "acknowledged":
        color = _COLOR_OK
        headline = (
            f"Signal acknowledged by <code>{html.escape(result.target_mac)}</code>"
        )
    elif result.state in ("no_response", "late_response", "cancelled"):
        color = _COLOR_WARN
        headline = html.escape(result.outcome_text)
    elif result.state == "rejected":
        color = _COLOR_ERROR
        headline = "Device rejected the Signal"
    elif result.state == "service_not_supported":
        color = _COLOR_ERROR
        headline = "Device reports Control/Signal as unsupported"
    elif result.state == "blocked":
        color = _COLOR_ERROR
        headline = "Signal blocked before transmission"
    else:
        color = _COLOR_ERROR
        headline = "Signal failed"

    facts: list[str] = []
    if result.state == "blocked" and result.error:
        facts.append(html.escape(result.error))
    elif result.state in ("rejected", "service_not_supported", "error") and result.error:
        facts.append(html.escape(result.error))
    if result.block_error is not None:
        facts.append(
            f"block error <code>0x{result.block_error:02x}</code> "
            f"{html.escape(result.block_error_text)}"
        )
    if result.rtt_ms is not None:
        facts.append(f"RTT {result.rtt_ms:.1f} ms")

    parts = [
        f"<span style='color:{color}'><b>{headline}</b></span>"
        + (" · " + " · ".join(facts) if facts else "")
    ]
    if result.state == "acknowledged":
        parts.append("<br>The LED flash on the device is the only confirmation.")
    elif result.state == "no_response":
        parts.append(
            "<br><b>No frame was retried.</b> Check the interface, VLAN and target "
            "before signalling again."
        )
    if result.warnings and result.state != "no_response":
        parts.append(
            "<br><b>Notes:</b> " + "; ".join(html.escape(w) for w in result.warnings)
        )
    return "".join(parts)


def write_result_html(result: WriteResult) -> str:
    """One-line summary of a guarded Set/Reset transaction."""
    if result.state == "acknowledged" and result.verification == "verified":
        color = _COLOR_OK
    elif result.verification == "mismatch" or result.state in (
        "rejected",
        "service_not_supported",
        "blocked",
        "target_unverified",
        "error",
    ):
        color = _COLOR_ERROR
    elif result.state in ("acknowledged", "no_response", "late_response"):
        color = _COLOR_WARN
    else:
        color = _COLOR_ERROR
    qualifier = (
        f" · qualifier <code>0x{result.block_qualifier:04x}</code>"
        if result.block_qualifier is not None
        else ""
    )
    parts = [
        f"<span style='color:{color}'><b>{html.escape(result.outcome_text)}</b></span>"
        f" · {html.escape(result.operation_text)}"
        f" · target <code>{html.escape(result.target_mac)}</code>"
        f" · Xid <code>0x{result.xid:08x}</code>{qualifier}"
    ]
    if result.rtt_ms is not None:
        parts.append(f" · RTT {result.rtt_ms:.3f} ms")
    if result.block_error is not None:
        parts.append(
            f"<br><b>Block error:</b> 0x{result.block_error:02x} "
            f"{html.escape(result.block_error_text)}"
        )
    parts.append(
        f"<br><b>Independent verification:</b> "
        f"<span style='color:{color}'>{html.escape(result.verification_text)}</span>"
    )
    if result.post_check_state != "not_attempted":
        parts.append(
            f"<br><b>Post-check ({html.escape(result.post_check_state)}):</b> "
            f"{html.escape(result.post_check_detail)}"
        )
    if result.warnings:
        parts.append(
            "<br><b>Notes:</b> " + "; ".join(html.escape(w) for w in result.warnings)
        )
    return "".join(parts)


def device_summary_html(device: DeviceIdentity) -> str:
    """Identity table shown on the Device Details tab."""
    warnings = "".join(f"<li>{html.escape(w)}</li>" for w in device.warnings)
    rows = [
        ("MAC address", device.mac),
        ("Interface", device.interface_id),
        ("NameOfStation", device.name_of_station or "<not set>"),
        ("IP address", device.ip_text),
        ("Subnet mask", display_addr(device.subnet_mask)),
        ("Gateway", display_addr(device.gateway)),
        (
            "Vendor ID",
            f"0x{device.vendor_id:04x}" if device.vendor_id is not None else "not advertised",
        ),
        (
            "Device ID",
            f"0x{device.device_id:04x}" if device.device_id is not None else "not advertised",
        ),
        ("Vendor / type of station", device.vendor_name or "not advertised"),
        ("Device role", device.role_text),
        ("Device options", device.options_text),
        ("Alias name", device.alias or "—"),
        (
            "Device instance",
            f"{device.device_instance[0]}/{device.device_instance[1]}"
            if device.device_instance
            else "—",
        ),
        (
            "OEM device ID",
            f"0x{device.oem_vendor_id:04x}/0x{device.oem_device_id:04x}"
            if device.oem_device_id is not None
            else "—",
        ),
        ("First seen", _iso_or_dash(device.first_seen)),
        ("Last seen", _iso_or_dash(device.last_seen)),
        ("Responses", str(device.response_count)),
        ("Duplicates", str(device.duplicate_responses)),
        (
            "Response time",
            f"{device.response_time_ms:.3f} ms" if device.response_time_ms is not None else "—",
        ),
        ("Last Xid", f"0x{device.last_xid:08x}" if device.last_xid is not None else "—"),
    ]
    table = "".join(
        f"<tr><td style='color:{_COLOR_MUTED};padding:3px 12px 3px 0'>{html.escape(k)}</td>"
        f"<td style='font-weight:600;padding:3px 0'>{html.escape(str(v))}</td></tr>"
        for k, v in rows
    )
    ip_info = ""
    if device.ip_block_info is not None:
        bits = []
        if device.ip_block_info & 0x0001:
            bits.append("IP set")
        if device.ip_block_info & 0x0002:
            bits.append("DHCP")
        if device.ip_block_info & 0x0080:
            bits.append("address conflict indicated")
        ip_info = (
            f"<p><b>IP BlockInfo:</b> 0x{device.ip_block_info:04x} "
            f"({', '.join(bits) if bits else 'IP not set'})</p>"
        )
    warning_html = f"<p><b>Warnings</b></p><ul>{warnings}</ul>" if warnings else ""
    return (
        "<style>table{width:100%;border-collapse:collapse}"
        "td{border-bottom:1px solid #eef2f7;vertical-align:top}</style>"
        f"<table>{table}</table>{ip_info}{warning_html}"
    )


def report_preview_html(
    *,
    interface_name: str | None,
    capture_total: int,
    devices: Sequence[DeviceIdentity],
    get_count: int,
    write_count: int,
    status_counts: Mapping[str, int],
    limitations: Iterable[str],
    sensitive_warning: str,
) -> str:
    """Session summary shown on the Logs & Reports tab."""
    device_rows = (
        "".join(
            f"<tr><td>{html.escape(d.mac)}</td><td>{html.escape(d.display_name)}</td>"
            f"<td>{html.escape(d.ip_text)}</td><td>{html.escape(d.vendor_device_text)}</td></tr>"
            for d in devices
        )
        or f"<tr><td colspan='4' style='color:{_COLOR_MUTED}'>No devices discovered.</td></tr>"
    )
    limitation_items = "".join(f"<li>{html.escape(x)}</li>" for x in limitations)
    return (
        "<style>table{width:100%;border-collapse:collapse}td{padding:5px;border-bottom:1px solid #dbe4ee}"
        "li{margin:4px 0}</style>"
        "<h2>Session summary</h2>"
        f"<p><b>Interface:</b> {html.escape(interface_name or 'none')}<br>"
        f"<b>Capture frames:</b> {capture_total}<br>"
        f"<b>Devices:</b> {len(devices)}<br>"
        f"<b>Read-only Get operations:</b> {get_count}<br>"
        f"<b>State-changing operations:</b> {write_count}<br>"
        f"<b>Tests:</b> passed {status_counts.get('passed', 0)}, "
        f"failed {status_counts.get('failed', 0)}, "
        f"skipped {status_counts.get('skipped', 0)}, "
        f"inconclusive {status_counts.get('inconclusive', 0)}</p>"
        "<h3>Devices</h3><table><tr><th>MAC</th><th>Name</th><th>IP</th>"
        f"<th>Vendor/Device</th></tr>{device_rows}</table>"
        f"<h3>Known limitations</h3><ul>{limitation_items}</ul>"
        f"<p style='color:{_COLOR_ERROR}'><b>Sensitive data:</b> "
        f"{html.escape(sensitive_warning)}</p>"
    )


def _iso_or_dash(value: Any) -> str:
    return iso_utc(value) or "—"
