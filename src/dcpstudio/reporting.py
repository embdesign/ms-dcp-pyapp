"""JSON and HTML report generation."""

from __future__ import annotations

import html
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import AppConfig
from .model import (
    DiscoveryResult,
    GetResult,
    LogRecordData,
    TestResult,
    WriteResult,
    iso_utc,
    report_metadata,
    utc_now,
)
from .transport.base import InterfaceInfo, Readiness

REPORT_SCHEMA_VERSION = 2

SENSITIVE_WARNING = (
    "Captures and reports can contain sensitive operational data: MAC addresses, "
    "station names, IP addresses, vendor/device identifiers, and network topology. "
    "Store and share them accordingly."
)

DISCLAIMER = (
    "Results are functional and interoperability observations from this tool. "
    "They are not an official PROFINET conformance certification."
)

KNOWN_LIMITATIONS: tuple[str, ...] = (
    "State-changing operations require explicit configuration mode, per-operation "
    "confirmation and fresh target revalidation. They are not automatic or batchable.",
    "Only ResetToFactorySettings modes 1, 2, 4 and 8 are transmitted. Modes 3 and 9 "
    "are documented by Wireshark but were not verified on hardware.",
    "A DCP acknowledgement is not proof that a value persisted or that a reset "
    "completed. Name/IP writes use one read-only read-back; reset uses an optional "
    "post-check that proves reachability only.",
    "DCP Signal (05/03) is sent as one unicast frame with qualifier 0x0000 and "
    "SignalValue 0x0100. It is not a guarded operation and changes no stored "
    "configuration; a DCP acknowledgement only proves the request was accepted, "
    "not that the LED was visible.",
    "DCP is Layer-2 link-local. Discovery does not traverse IP routers and is "
    "restricted to the selected interface's broadcast domain and VLAN.",
    "A missing Identify response is not proof that a device is absent; multicast "
    "filtering, VLAN boundaries, interface selection, privileges, or timeout settings "
    "may explain it.",
    "DCP discovery does not prove that an IP address is unused and does not detect all "
    "address conflicts.",
    "Unknown or vendor-specific blocks are preserved for inspection but not interpreted.",
    "Device capability is not inferred from the manufacturer name.",
    "No cyclic PROFINET IO, controller commissioning, firmware flashing, DHCP, or "
    "PROFINET CM/DCE-RPC functionality is implemented.",
    "Report timestamps come from the host clock; capture timestamps may come from the "
    "capture driver.",
    "This report is not a PROFINET conformance certificate.",
)


@dataclass(slots=True)
class ReportContext:
    interface: InterfaceInfo | None = None
    readiness: Readiness | None = None
    config: AppConfig = field(default_factory=AppConfig)
    discovery: DiscoveryResult | None = None
    discoveries: list[DiscoveryResult] = field(default_factory=list)
    get_results: list[GetResult] = field(default_factory=list)
    write_results: list[WriteResult] = field(default_factory=list)
    test_results: list[TestResult] = field(default_factory=list)
    logs: list[LogRecordData] = field(default_factory=list)
    capture_stats: dict[str, int] = field(default_factory=dict)
    before_after: list[dict[str, Any]] = field(default_factory=list)
    extra_notes: list[str] = field(default_factory=list)


def _interface_dict(interface: InterfaceInfo | None) -> dict[str, Any] | None:
    if interface is None:
        return None
    return {
        "id": interface.id,
        "name": interface.name,
        "description": interface.description,
        "mac": interface.mac,
        "ipv4": list(interface.ipv4_addresses),
        "ipv6": list(interface.ipv6_addresses),
        "is_up": interface.is_up,
        "is_running": interface.is_running,
        "is_loopback": interface.is_loopback,
        "is_virtual": interface.is_virtual,
        "kind": interface.kind,
    }


def _xid_text(value: int | None) -> str:
    return f"0x{value:08x}" if value is not None else "—"


def build_report(context: ReportContext) -> dict[str, Any]:
    discoveries = list(context.discoveries)
    if context.discovery is not None and context.discovery not in discoveries:
        discoveries.append(context.discovery)
    status_counts: dict[str, int] = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "inconclusive": 0,
    }
    for result in context.test_results:
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
    limitations = list(KNOWN_LIMITATIONS)
    for note in context.extra_notes:
        if note not in limitations:
            limitations.append(note)
    observations = list(context.before_after)
    for write in context.write_results:
        if write.before_identity is None and write.after_identity is None:
            continue
        observations.append(
            {
                "xid": write.xid,
                "operation": write.operation,
                "target_mac": write.target_mac,
                "state": write.state,
                "verification": write.verification,
                "post_check_state": write.post_check_state,
                "before": (
                    write.before_identity.to_dict() if write.before_identity else None
                ),
                "after": (
                    write.after_identity.to_dict() if write.after_identity else None
                ),
            }
        )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "metadata": report_metadata(),
        "generated_at": iso_utc(utc_now()),
        "sensitive_data_warning": SENSITIVE_WARNING,
        "disclaimer": DISCLAIMER,
        "test_configuration": {
            "interface": _interface_dict(context.interface),
            "timeout_s": context.config.timeout_s,
            "response_delay_factor": context.config.response_delay_factor,
            "vlan_id": context.config.vlan_id,
            "min_request_interval_s": context.config.min_request_interval_s,
            "capture": dict(context.capture_stats),
        },
        "readiness": context.readiness.to_dict() if context.readiness else None,
        "latest_discovery": context.discovery.to_dict() if context.discovery else None,
        "discovery_runs": [d.to_dict() for d in discoveries],
        "get_operations": [g.to_dict() for g in context.get_results],
        "write_operations": [w.to_dict() for w in context.write_results],
        "test_summary": status_counts,
        "test_results": [r.to_dict() for r in context.test_results],
        "before_after_observations": observations,
        "known_limitations": limitations,
        "log_events": [record.to_dict() for record in context.logs],
    }


def write_json_report(path: str | Path, context: ReportContext) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(context)
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def write_html_report(path: str | Path, context: ReportContext) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(context), encoding="utf-8")
    return path


def report_filename(prefix: str = "dcp-report", *, extension: str = "json") -> str:
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}.{extension}"


def render_html_report(context: ReportContext) -> str:
    report = build_report(context)
    e = html.escape
    interface = report["test_configuration"]["interface"] or {}
    readiness = report["readiness"] or {}
    latest = report["latest_discovery"] or {}
    devices = latest.get("devices", []) if latest else []
    transactions = latest.get("transactions", []) if latest else []
    tests = report["test_results"]
    summary = report["test_summary"]

    def device_rows() -> str:
        if not devices:
            return '<tr><td colspan="9" class="empty">No devices discovered.</td></tr>'
        rows = []
        for d in devices:
            ip_value = d.get("ip_address")
            ip_display = "<not set>" if not ip_value or ip_value == "0.0.0.0" else str(ip_value)
            rows.append(
                "<tr>"
                f"<td class='mono'>{e(str(d.get('mac', '')))}</td>"
                f"<td>{e(str(d.get('name_of_station') or '<not set>'))}</td>"
                f"<td class='mono'>{e(ip_display)}</td>"
                f"<td class='mono'>{e(str(d.get('subnet_mask') or '—'))}</td>"
                f"<td class='mono'>{e(str(d.get('gateway') or '—'))}</td>"
                f"<td class='mono'>{e(str(d.get('vendor_id_hex') or '—'))}</td>"
                f"<td class='mono'>{e(str(d.get('device_id_hex') or '—'))}</td>"
                f"<td>{e(', '.join(d.get('device_role_names') or []) or 'not advertised')}</td>"
                f"<td class='mono'>{e(str(d.get('response_time_ms') if d.get('response_time_ms') is not None else '—'))}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def transaction_rows() -> str:
        if not transactions:
            return '<tr><td colspan="6" class="empty">No transactions recorded.</td></tr>'
        rows = []
        for t in transactions:
            rows.append(
                "<tr>"
                f"<td class='mono'>{e(str(t.get('timestamp', '')))}</td>"
                f"<td>{e(str(t.get('event', '')))}</td>"
                f"<td>{e(str(t.get('outcome', '')))}</td>"
                f"<td class='mono'>{e(_xid_text(t.get('xid')))}</td>"
                f"<td class='mono'>{e(str(t.get('peer_mac') or '—'))}</td>"
                f"<td>{e(str(t.get('detail') or ''))}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def get_rows() -> str:
        operations = report.get("get_operations", [])
        if not operations:
            return '<tr><td colspan="7" class="empty">No read-only Get operations.</td></tr>'
        rows = []
        for operation in operations:
            rows.append(
                "<tr>"
                f"<td class='mono'>{e(str(operation.get('finished_at', '')))}</td>"
                f"<td class='mono'>{e(str(operation.get('target_mac', '')))}</td>"
                f"<td>{e(str(operation.get('outcome_text', operation.get('outcome', ''))))}</td>"
                f"<td class='mono'>{e(_xid_text(operation.get('xid')))}</td>"
                f"<td>{e(str(len(operation.get('blocks', []))))}</td>"
                f"<td>{e(str(len(operation.get('block_errors', []))))}</td>"
                f"<td class='mono'>{e(str(operation.get('rtt_ms') if operation.get('rtt_ms') is not None else '—'))}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def write_rows() -> str:
        operations = report.get("write_operations", [])
        if not operations:
            return '<tr><td colspan="8" class="empty">No state-changing operations.</td></tr>'
        rows = []
        for operation in operations:
            before = operation.get("before_identity") or {}
            after = operation.get("after_identity") or {}
            before_name = before.get("name_of_station") or "<not set>"
            after_name = after.get("name_of_station") or "<not set>"
            rows.append(
                "<tr>"
                f"<td class='mono'>{e(str(operation.get('finished_at', '')))}</td>"
                f"<td class='mono'>{e(str(operation.get('target_mac', '')))}</td>"
                f"<td>{e(str(operation.get('operation_text', '')))}</td>"
                f"<td class='mono'>{e(str(operation.get('block_qualifier_hex') or '—'))}</td>"
                f"<td>{e(str(operation.get('outcome_text', '')))}</td>"
                f"<td>{e(str(operation.get('verification', '')))}</td>"
                f"<td>{e(str(operation.get('post_check_state', 'not_attempted')))}</td>"
                f"<td>{e(f'{before_name} → {after_name}')}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def test_rows() -> str:
        if not tests:
            return '<tr><td colspan="6" class="empty">No tests were run.</td></tr>'
        rows = []
        for t in tests:
            status = str(t.get("status", ""))
            rows.append(
                f"<tr class='status-{e(status)}'>"
                f"<td class='mono'>{e(str(t.get('test_id', '')))}</td>"
                f"<td>{e(str(t.get('name', '')))}</td>"
                f"<td>{e(str(t.get('category', '')))}</td>"
                f"<td class='status'>{e(status.upper())}</td>"
                f"<td class='mono'>{e(str(t.get('duration_ms', '')))}</td>"
                f"<td>{e(str(t.get('detail', '')))}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def limitations_html() -> str:
        return "".join(f"<li>{e(item)}</li>" for item in report["known_limitations"])

    def notes_html() -> str:
        notes = latest.get("warnings", []) if latest else []
        if not notes:
            return '<p class="muted">No discovery warnings.</p>'
        return "".join(f"<li>{e(str(item))}</li>" for item in notes)

    def before_after_html() -> str:
        if not context.before_after and not report.get("before_after_observations"):
            return (
                '<p class="muted">No before/after observations. No state-changing '
                "operation was performed in this session.</p>"
            )
        return f"<pre>{e(json.dumps(report.get('before_after_observations', []), indent=2, ensure_ascii=False))}</pre>"

    def logs_html() -> str:
        if not context.logs:
            return '<p class="muted">No log events.</p>'
        rows = []
        for record in context.logs[-500:]:
            rows.append(
                "<tr>"
                f"<td class='mono'>{e(iso_utc(record.timestamp) or '')}</td>"
                f"<td>{e(record.level)}</td>"
                f"<td class='mono'>{e(record.event)}</td>"
                f"<td>{e(record.message)}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    selected = e(
        f"{interface.get('name', '—')} ({interface.get('mac') or 'no MAC'})"
        if interface
        else "No interface selected"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DCP Studio report</title>
<style>
:root {{ color-scheme: light; --ink:#16212b; --muted:#64748b; --line:#dbe4ee;
  --bg:#f5f8fc; --card:#ffffff; --accent:#0b6bcb; --ok:#137a4b; --bad:#b42318;
  --warn:#a15c00; --skip:#5b6472; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink);
  font:14px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }}
main {{ max-width:1180px; margin:0 auto; padding:32px 24px 60px; }}
header {{ display:flex; justify-content:space-between; gap:24px; align-items:flex-start;
  margin-bottom:24px; }}
h1 {{ margin:0 0 4px; font-size:28px; letter-spacing:-.02em; }}
h2 {{ font-size:18px; margin:0 0 14px; }}
.sub {{ color:var(--muted); }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:14px;
  padding:20px; margin:16px 0; box-shadow:0 1px 2px rgba(15,35,60,.04); }}
.warn {{ border-left:4px solid var(--warn); background:#fff8ec; }}
.danger {{ border-left:4px solid var(--bad); background:#fff4f2; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:14px; }}
.kv {{ background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:12px; }}
.kv .k {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
.kv .v {{ font-weight:600; overflow-wrap:anywhere; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ text-align:left; color:var(--muted); font-size:11px; text-transform:uppercase;
  letter-spacing:.06em; border-bottom:2px solid var(--line); padding:9px 8px; }}
td {{ border-bottom:1px solid var(--line); padding:9px 8px; vertical-align:top; }}
tr:last-child td {{ border-bottom:0; }}
.mono {{ font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:12px; }}
.muted, .empty {{ color:var(--muted); }}
.status-PASSED .status {{ color:var(--ok); font-weight:700; }}
.status-FAILED .status {{ color:var(--bad); font-weight:700; }}
.status-SKIPPED .status {{ color:var(--skip); font-weight:700; }}
.status-INCONCLUSIVE .status {{ color:var(--warn); font-weight:700; }}
.pill {{ display:inline-block; padding:3px 9px; border-radius:999px; background:var(--bg);
  border:1px solid var(--line); font-size:12px; font-weight:600; }}
pre {{ overflow:auto; background:#0e1726; color:#dbe7f5; padding:14px; border-radius:10px;
  font-size:12px; }}
ul {{ margin:8px 0 0 20px; padding:0; }}
footer {{ color:var(--muted); font-size:12px; margin-top:28px; }}
</style>
</head>
<body><main>
<header>
  <div>
    <h1>DCP Studio — PROFINET DCP Report</h1>
    <div class="sub">Generated {e(str(report['generated_at']))} · guarded writes</div>
  </div>
  <span class="pill">Functional / interoperability</span>
</header>

<div class="card danger"><strong>Sensitive data.</strong> {e(SENSITIVE_WARNING)}</div>
<div class="card warn"><strong>Not a conformance certificate.</strong> {e(DISCLAIMER)}</div>

<div class="card">
  <h2>Test configuration</h2>
  <div class="grid">
    <div class="kv"><div class="k">Interface</div><div class="v">{selected}</div></div>
    <div class="kv"><div class="k">Timeout</div><div class="v">{e(str(report['test_configuration']['timeout_s']))} s</div></div>
    <div class="kv"><div class="k">Response delay factor</div><div class="v">{e(str(report['test_configuration']['response_delay_factor']))}</div></div>
    <div class="kv"><div class="k">VLAN</div><div class="v">{e(str(report['test_configuration']['vlan_id']) if report['test_configuration']['vlan_id'] else 'untagged')}</div></div>
    <div class="kv"><div class="k">Readiness</div><div class="v">{e(str(readiness.get('message', 'not evaluated')))}</div></div>
    <div class="kv"><div class="k">Capture frames</div><div class="v">{e(str(report['test_configuration']['capture'].get('total', 0)))}</div></div>
  </div>
</div>

<div class="card">
  <h2>Discovery summary</h2>
  <div class="grid">
    <div class="kv"><div class="k">Outcome</div><div class="v">{e(str(latest.get('outcome', 'not run')))}</div></div>
    <div class="kv"><div class="k">Devices</div><div class="v">{len(devices)}</div></div>
    <div class="kv"><div class="k">Xid</div><div class="v mono">{e(_xid_text(latest.get('xid')))}</div></div>
    <div class="kv"><div class="k">Duplicate responses</div><div class="v">{e(str(latest.get('duplicate_responses', 0)))}</div></div>
    <div class="kv"><div class="k">Late responses</div><div class="v">{e(str(latest.get('late_responses', 0)))}</div></div>
    <div class="kv"><div class="k">Unmatched responses</div><div class="v">{e(str(latest.get('unmatched_responses', 0)))}</div></div>
  </div>
  <h2 style="margin-top:18px">Warnings</h2>
  <ul>{notes_html()}</ul>
</div>

<div class="card">
  <h2>Read-only Get operations</h2>
  <div style="overflow:auto">
  <table>
    <thead><tr><th>UTC time</th><th>Target MAC</th><th>Outcome</th><th>Xid</th>
    <th>Blocks</th><th>Block errors</th><th>RTT ms</th></tr></thead>
    <tbody>{get_rows()}</tbody>
  </table>
  </div>
</div>

<div class="card">
  <h2>State-changing operations (guarded)</h2>
  <div style="overflow:auto">
  <table>
    <thead><tr><th>UTC time</th><th>Target MAC</th><th>Operation</th><th>Qualifier</th>
    <th>Outcome</th><th>Verification</th><th>Post-check</th><th>Name before → after</th></tr></thead>
    <tbody>{write_rows()}</tbody>
  </table>
  </div>
</div>

<div class="card">
  <h2>Devices</h2>
  <div style="overflow:auto">
  <table>
    <thead><tr><th>MAC</th><th>NameOfStation</th><th>IP</th><th>Mask</th><th>Gateway</th>
    <th>Vendor ID</th><th>Device ID</th><th>Role</th><th>RTT ms</th></tr></thead>
    <tbody>{device_rows()}</tbody>
  </table>
  </div>
</div>

<div class="card">
  <h2>Transaction log</h2>
  <div style="overflow:auto">
  <table>
    <thead><tr><th>UTC time</th><th>Event</th><th>Outcome</th><th>Xid</th><th>Peer</th><th>Detail</th></tr></thead>
    <tbody>{transaction_rows()}</tbody>
  </table>
  </div>
</div>

<div class="card">
  <h2>Functional test results</h2>
  <div class="grid">
    <div class="kv"><div class="k">Passed</div><div class="v">{summary.get('passed', 0)}</div></div>
    <div class="kv"><div class="k">Failed</div><div class="v">{summary.get('failed', 0)}</div></div>
    <div class="kv"><div class="k">Skipped</div><div class="v">{summary.get('skipped', 0)}</div></div>
    <div class="kv"><div class="k">Inconclusive</div><div class="v">{summary.get('inconclusive', 0)}</div></div>
  </div>
  <div style="overflow:auto; margin-top:16px">
  <table>
    <thead><tr><th>ID</th><th>Test</th><th>Category</th><th>Status</th><th>ms</th><th>Detail</th></tr></thead>
    <tbody>{test_rows()}</tbody>
  </table>
  </div>
</div>

<div class="card">
  <h2>Before / after observations</h2>
  {before_after_html()}
</div>

<div class="card">
  <h2>Known limitations</h2>
  <ul>{limitations_html()}</ul>
</div>

<div class="card">
  <h2>Log events (last 500)</h2>
  <div style="overflow:auto">
  <table>
    <thead><tr><th>UTC time</th><th>Level</th><th>Event</th><th>Message</th></tr></thead>
    <tbody>{logs_html()}</tbody>
  </table>
  </div>
</div>

<footer>DCP Studio {e(str(report['metadata']['version']))} · report schema {REPORT_SCHEMA_VERSION} · {e(str(report['generated_at']))}</footer>
</main></body></html>
"""


def summarize_statuses(results: Iterable[TestResult]) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "skipped": 0, "inconclusive": 0}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    return counts
