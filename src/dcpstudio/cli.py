"""Headless command line interface for DCP Studio.

The CLI is a thin adapter over the same services, codec and safety model the
GUI uses. It adds no protocol behaviour of its own:

* read-only commands (``interfaces``, ``discover``, ``get``, ``pcap``) never
  change equipment;
* ``signal`` is the unguarded identification action, one unicast frame, rate
  limited, never retried;
* ``set-name``, ``set-ip`` and ``reset`` require an explicit ``--confirm``,
  perform a fresh unicast Identify, and go through ``WriteService`` once;
* ``tests`` runs the read-only functional checks by default. The state-changing
  ``write.*`` cases run only with ``--include-writes --confirm --mac``.

Operator-facing text and parameters come from :mod:`dcpstudio.operations`, so
the consequences shown by the CLI cannot drift from the GUI.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from . import APP_NAME, __version__
from .codec import parse_mac
from .config import AppConfig
from .constants import (
    DEFAULT_MIN_REQUEST_INTERVAL_S,
    DEFAULT_POST_CHECK_WINDOW_S,
    DEFAULT_RESPONSE_DELAY_FACTOR,
    SUPPORTED_RESET_MODES,
)
from .inventory import (
    PlanFinding,
    compare_plan,
    inventory_csv,
    inventory_rows,
    parse_plan_csv,
)
from .logging_setup import EventLogger
from .model import DeviceIdentity, DiscoveryResult, GetResult, WriteResult, iso_utc
from .monitor import (
    MAX_MONITOR_CYCLES,
    MAX_MONITOR_INTERVAL_S,
    MIN_MONITOR_INTERVAL_S,
    MonitorConfig,
    MonitorRun,
)
from .operations import (
    OperationSpec,
    confirmation_for,
    legacy_reset_spec,
    reset_mode_spec,
    set_ip_spec,
    set_name_spec,
)
from .pcap_io import PcapError, analyze_pcap
from .reporting import ReportContext, summarize_statuses, write_html_report, write_json_report
from .services.capture import FrameRouter
from .services.discovery import DiscoveryConfig, DiscoveryService
from .services.get import GET_PRESETS, GetConfig, GetService
from .services.monitor import MonitorService
from .services.signal import SignalService
from .services.write import (
    WriteAuthorization,
    WriteConfig,
    WriteRequest,
    WriteService,
    identity_text,
)
from .session import build_services, probe_readiness
from .testrunner.cases import TEST_CASES
from .testrunner.runner import TestRunner
from .transport.base import DcpTransport, TransportError
from .transport.interfaces import (
    MOCK_INTERFACE_ID,
    InterfaceInfo,
    enumerate_interfaces,
    platform_label,
)
from .validation import (
    validate_discovery_timeout,
    validate_ip_suite,
    validate_mac,
    validate_response_delay_factor,
    validate_station_name,
    validate_vlan,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNKNOWN = 2

CLI_COMMANDS = frozenset(
    {
        "interfaces",
        "discover",
        "inventory",
        "monitor",
        "get",
        "signal",
        "set-name",
        "set-ip",
        "reset",
        "tests",
        "pcap",
    }
)

_Progress = Callable[[str], None] | None


class _CliError(RuntimeError):
    """Operator-readable command line error (no traceback)."""


# --------------------------------------------------------------------- utils
def _emit_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _progress(args: argparse.Namespace) -> _Progress:
    if getattr(args, "quiet", False):
        return None

    def report(message: str) -> None:
        print(f"… {message}", file=sys.stderr)

    return report


def _resolve_interface(value: str) -> InterfaceInfo:
    lookup = value.strip()
    if lookup.lower() in {"demo", "mock", "demo0", MOCK_INTERFACE_ID}:
        lookup = MOCK_INTERFACE_ID
    candidates = enumerate_interfaces(include_mock=True)
    for item in candidates:
        if item.id == lookup:
            return item
    for item in candidates:
        if item.name == lookup:
            return item
    raise _CliError(
        f"Unknown interface {value!r}. Run 'dcp-cli interfaces' to list available interfaces."
    )


def _validated_mac(value: str, *, unicast: bool = True) -> str:
    report = validate_mac(value)
    if not report.ok:
        raise _CliError(f"Invalid target MAC {value!r}: {report.summary()}")
    if unicast:
        raw = parse_mac(value.strip())
        if raw[0] & 1:
            raise _CliError(
                "Target must be exactly one unicast device MAC; multicast, broadcast and "
                "batch targets are not supported."
            )
    return value.strip()


def _validate_common(args: argparse.Namespace, *, discovery: bool) -> None:
    report = validate_vlan(getattr(args, "vlan", None))
    if not report.ok:
        raise _CliError(report.summary())
    if discovery:
        report = validate_discovery_timeout(args.timeout)
        if not report.ok:
            raise _CliError(report.summary())
    elif not 0.5 <= float(args.timeout) <= 60.0:
        raise _CliError("Timeout must be 0.5..60 seconds")
    if hasattr(args, "response_delay_factor"):
        report = validate_response_delay_factor(args.response_delay_factor)
        if not report.ok:
            raise _CliError(report.summary())
    if float(args.min_interval) < 0:
        raise _CliError("--min-interval must not be negative")


def _parse_selector(text: str) -> tuple[int, int]:
    parts = re.split(r"[/:]", text.strip())
    if len(parts) != 2:
        raise _CliError(
            f"Invalid selector {text!r}; expected OPTION/SUBOPTION, for example 0x02/0x02"
        )
    try:
        option, suboption = int(parts[0], 0), int(parts[1], 0)
    except ValueError as exc:
        raise _CliError(f"Invalid selector {text!r}: {exc}") from exc
    if not (0 <= option <= 0xFF and 0 <= suboption <= 0xFF):
        raise _CliError("Selector option and sub-option must be 0..255")
    return option, suboption


def _app_config(args: argparse.Namespace, interface: InterfaceInfo) -> AppConfig:
    return AppConfig(
        last_interface_id=interface.id,
        timeout_s=float(args.timeout),
        response_delay_factor=int(
            getattr(args, "response_delay_factor", DEFAULT_RESPONSE_DELAY_FACTOR)
        ),
        vlan_id=getattr(args, "vlan", None),
        min_request_interval_s=float(args.min_interval),
    )


def _maybe_write_report(
    args: argparse.Namespace,
    session: _Session,
    *,
    discovery: DiscoveryResult | None = None,
    get_result: GetResult | None = None,
    write_result: WriteResult | None = None,
    test_results: Sequence[Any] = (),
) -> None:
    target = getattr(args, "report", None)
    if not target:
        return
    path = Path(target)
    context = ReportContext(
        interface=session.interface,
        readiness=session.transport.readiness(),
        config=_app_config(args, session.interface),
        discovery=discovery,
        get_results=[get_result] if get_result is not None else [],
        write_results=[write_result] if write_result is not None else [],
        test_results=list(test_results),
    )
    if path.suffix.lower() in (".html", ".htm"):
        written = write_html_report(path, context)
    else:
        written = write_json_report(path, context)
    print(f"Report written to {written}", file=sys.stderr)


# ------------------------------------------------------------------- session
class _Session:
    """Thin adapter over :func:`dcpstudio.session.build_services`.

    Keeps the attribute names the command handlers already use, so the CLI and
    the GUI are wired by the same code.
    """

    def __init__(self, interface: InterfaceInfo, *, min_interval_s: float) -> None:
        self.interface = interface
        self.logger = EventLogger()
        self._services = build_services(
            interface,
            min_interval_s=min_interval_s,
            event_log=self.logger.info,
        )

    @property
    def transport(self) -> DcpTransport:
        return self._services.transport

    @property
    def router(self) -> FrameRouter:
        return self._services.router

    @property
    def discovery(self) -> DiscoveryService:
        return self._services.discovery

    @property
    def getter(self) -> GetService:
        return self._services.getter

    @property
    def writer(self) -> WriteService:
        return self._services.writer

    @property
    def signal(self) -> SignalService:
        assert self._services.signal is not None
        return self._services.signal

    @property
    def monitor(self) -> MonitorService:
        return self._services.monitor

    def __enter__(self) -> _Session:
        self.transport.start_capture()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._services.close()
        return False


# ---------------------------------------------------------------- formatting
def _block_value_text(block) -> str:
    raw = block.value
    if not raw:
        return "<empty>"
    try:
        text = raw.rstrip(b"\x00").decode("ascii")
    except UnicodeDecodeError:
        return raw.hex()
    if text and all(0x20 <= ord(ch) <= 0x7E for ch in text):
        return repr(text)
    return raw.hex()


def _print_discovery(result: DiscoveryResult) -> None:
    print(
        f"Discovery on {result.interface_id} (Xid 0x{result.xid:08x}) — {result.outcome_text}"
    )
    print(
        f"Timeout {result.timeout_s:.1f} s, ResponseDelayFactor "
        f"{result.response_delay_factor}, duration {result.duration_ms:.0f} ms"
    )
    if result.identify_filter_name is not None:
        print(f"NameOfStation filter: {result.identify_filter_name!r}")
    if result.error:
        print(f"Error: {result.error}")
    if result.devices:
        print()
        print(
            f"{'MAC':<17}  {'Name':<24}  {'IP':<15}  {'Vendor/Device':<17}  Role"
        )
        for device in result.devices:
            print(
                f"{device.mac:<17}  {device.display_name:<24}  {device.ip_text:<15}  "
                f"{device.vendor_device_text:<17}  {device.role_text}"
            )
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)


def _print_get(result: GetResult) -> None:
    print(f"Get to {result.target_mac} — {result.outcome_text}")
    print(
        f"Xid 0x{result.xid:08x}, {len(result.selectors)} selector(s), "
        f"duration {result.duration_ms:.0f} ms"
    )
    if result.rtt_ms is not None:
        print(f"Round-trip time: {result.rtt_ms:.1f} ms")
    if result.identity is not None:
        identity = result.identity
        print(
            f"Identity: name={identity.display_name}, IP={identity.ip_text}, "
            f"Vendor/Device={identity.vendor_device_text}"
        )
    if result.blocks:
        print("Blocks:")
        for block in result.blocks:
            info = f" [{block.block_info}]" if block.block_info is not None else ""
            print(
                f"  0x{block.option:02x}/0x{block.suboption:02x} "
                f"{block.suboption_name}{info} = {_block_value_text(block)}"
            )
    if result.block_errors:
        print(f"Block errors: {result.block_error_text}")
    if result.error:
        print(f"Error: {result.error}")
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)


def _print_monitor(run: MonitorRun) -> None:
    config = run.config
    print(
        f"Monitor on {run.interface_id} — {len(run.cycles)} cycle(s), "
        f"{len(run.changes)} change(s)"
    )
    print(
        f"Interval {config.interval_s:.1f} s, timeout {config.timeout_s:.1f} s, "
        f"ResponseDelayFactor {config.response_delay_factor}"
    )
    for cycle in run.cycles:
        print(
            f"  cycle {cycle.index + 1}: {cycle.device_count} device(s) — "
            f"{cycle.outcome_text} ({cycle.duration_ms:.0f} ms)"
        )
    if run.changes:
        print()
        print(f"{'Time (UTC)':<24}  {'Change':<8}  {'MAC':<17}  {'Name':<20}  Detail")
        for change in run.changes:
            detail = (
                f"{change.field_label}: {change.before} -> {change.after}"
                if change.field is not None
                else change.device_text
            )
            print(
                f"{iso_utc(change.timestamp) or '':<24}  {str(change.kind):<8}  "
                f"{change.mac:<17}  {change.device_text:<20}  {detail}"
            )
    if run.cancelled:
        print("Monitor stopped before all planned cycles completed.")
    if run.error:
        print(f"Error: {run.error}")


def _print_write(result: WriteResult) -> None:
    print(f"{result.operation_text} → {result.target_mac}: {result.outcome_text}")
    print(f"Xid 0x{result.xid:08x}, state {result.state}")
    if result.parameters:
        parameters = ", ".join(f"{key}={value}" for key, value in result.parameters.items())
        print(f"Parameters: {parameters}")
    if result.block_qualifier is not None:
        print(f"BlockQualifier: 0x{result.block_qualifier:04x}")
    if result.reset_mode is not None:
        print(f"Reset mode: {result.reset_mode}")
    print(f"Verification: {result.verification_text}")
    if result.post_check_state != "not_attempted":
        print(f"Post-check ({result.post_check_state}): {result.post_check_detail}")
    if result.error:
        print(f"Error: {result.error}")
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)


def _print_operation_spec(
    spec: OperationSpec,
    *,
    target_mac: str,
    interface: str,
    stream: Any = None,
) -> None:
    out = stream or sys.stdout
    print(f"Operation: {spec.operation_text} ({spec.destructiveness})", file=out)
    print(f"Interface: {interface}", file=out)
    print(f"Target MAC: {target_mac}", file=out)
    print("Parameters:", file=out)
    for key, value in spec.proposed_parameters.items():
        print(f"  {key}: {value}", file=out)
    print("Consequences:", file=out)
    for line in spec.consequences:
        print(f"  - {line}", file=out)


# ---------------------------------------------------------------- exit codes
def _discovery_exit_code(result: DiscoveryResult) -> int:
    if result.error:
        return EXIT_FAILED
    if result.cancelled or not result.devices:
        return EXIT_UNKNOWN
    return EXIT_OK


def _get_exit_code(result: GetResult) -> int:
    if result.state == "response_received" and not result.block_errors:
        return EXIT_OK
    if result.state in ("no_response", "late_response", "cancelled"):
        return EXIT_UNKNOWN
    return EXIT_FAILED


def _write_exit_code(result: WriteResult) -> int:
    if result.state == "acknowledged" and result.verification != "mismatch":
        return EXIT_OK
    if result.state in ("no_response", "late_response"):
        return EXIT_UNKNOWN
    if result.state == "cancelled":
        return EXIT_UNKNOWN if result.transmitted else EXIT_FAILED
    return EXIT_FAILED


# ------------------------------------------------------------------ commands
def _interface_readiness(item: InterfaceInfo) -> dict[str, Any]:
    return probe_readiness(item).to_dict()


def _cmd_interfaces(args: argparse.Namespace) -> int:
    items = enumerate_interfaces(include_mock=True)
    readiness = {
        item.id: _interface_readiness(item) for item in items
    } if args.readiness else {}
    if args.json:
        _emit_json(
            {
                "application": APP_NAME,
                "version": __version__,
                "platform": platform_label(),
                "interfaces": [
                    {
                        "id": item.id,
                        "name": item.name,
                        "description": item.description,
                        "mac": item.mac,
                        "ipv4": list(item.ipv4_addresses),
                        "ipv6": list(item.ipv6_addresses),
                        "link": item.link_text,
                        "kind": item.kind,
                        "is_loopback": item.is_loopback,
                        "is_virtual": item.is_virtual,
                        "readiness": readiness.get(item.id),
                    }
                    for item in items
                ],
            }
        )
        return EXIT_OK
    print(f"{APP_NAME} {__version__} — interfaces on {platform_label()}")
    print(f"{'ID':<28}  {'Name':<14}  {'MAC':<17}  {'IPv4':<15}  {'Link':<16}  Kind")
    for item in items:
        print(
            f"{item.id:<28}  {item.name:<14}  {item.mac or '—':<17}  "
            f"{item.ipv4_addresses[0] if item.ipv4_addresses else '—':<15}  "
            f"{item.link_text:<16}  {item.kind}"
        )
        report = readiness.get(item.id)
        if report is not None:
            print(f"{'':<28}  {report['message']}")
            for hint in report.get("hints") or []:
                print(f"{'':<28}  hint: {hint}")
    return EXIT_OK


def _cmd_discover(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=True)
    if args.name is not None:
        if not args.name:
            raise _CliError("The Identify NameOfStation filter must not be empty")
        report = validate_station_name(args.name)
        if not report.ok:
            raise _CliError(f"Invalid Identify NameOfStation filter: {report.summary()}")
    unicast = _validated_mac(args.unicast) if args.unicast else None
    interface = _resolve_interface(args.interface)
    with _Session(interface, min_interval_s=args.min_interval) as session:
        result = session.discovery.discover(
            DiscoveryConfig(
                timeout_s=args.timeout,
                response_delay_factor=args.response_delay_factor,
                vlan_id=args.vlan,
                unicast_mac=unicast,
                min_request_interval_s=args.min_interval,
                identify_filter_name=args.name,
            ),
            progress=_progress(args),
        )
        _maybe_write_report(args, session, discovery=result)
        if args.json:
            _emit_json(result.to_dict())
        else:
            _print_discovery(result)
        return _discovery_exit_code(result)


def _cmd_inventory(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=True)
    if args.name is not None:
        if not args.name:
            raise _CliError("The Identify NameOfStation filter must not be empty")
        report = validate_station_name(args.name)
        if not report.ok:
            raise _CliError(f"Invalid Identify NameOfStation filter: {report.summary()}")
    interface = _resolve_interface(args.interface)
    with _Session(interface, min_interval_s=args.min_interval) as session:
        result = session.discovery.discover(
            DiscoveryConfig(
                timeout_s=args.timeout,
                response_delay_factor=args.response_delay_factor,
                vlan_id=args.vlan,
                min_request_interval_s=args.min_interval,
                identify_filter_name=args.name,
            ),
            progress=_progress(args),
        )
        rows = inventory_rows(result.devices)
        csv_path: Path | None = Path(args.csv).expanduser() if args.csv else None
        if csv_path is not None:
            try:
                csv_path.parent.mkdir(parents=True, exist_ok=True)
                csv_path.write_text(inventory_csv(result.devices), encoding="utf-8")
            except OSError as exc:
                raise _CliError(f"Could not write inventory CSV: {exc}") from exc
        plan_findings: list[PlanFinding] = []
        plan_warnings: list[str] = []
        if args.plan:
            try:
                plan_text = Path(args.plan).expanduser().read_text(encoding="utf-8")
            except OSError as exc:
                raise _CliError(f"Could not read plan file: {exc}") from exc
            entries, plan_warnings = parse_plan_csv(plan_text)
            plan_findings = compare_plan(result.devices, entries)
        if args.json:
            _emit_json(
                {
                    "interface": result.interface_id,
                    "outcome": result.outcome,
                    "devices": rows,
                    "csv_path": str(csv_path) if csv_path else None,
                    "plan": (
                        {
                            "findings": [finding.to_dict() for finding in plan_findings],
                            "warnings": plan_warnings,
                        }
                        if args.plan
                        else None
                    ),
                }
            )
        else:
            _print_discovery(result)
            if csv_path is not None:
                print(f"Inventory written to {csv_path} ({len(rows)} device(s))")
            for warning in plan_warnings:
                print(f"plan warning: {warning}", file=sys.stderr)
            if args.plan:
                if plan_findings:
                    print()
                    print(f"Plan check: {len(plan_findings)} finding(s)")
                    for finding in plan_findings:
                        print(f"  {finding.kind}: {finding.detail}")
                else:
                    print("Plan check: no differences.")
        if args.plan and plan_findings and args.strict:
            return EXIT_FAILED
        return _discovery_exit_code(result)


def _cmd_monitor(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=True)
    interval = float(args.interval)
    if not MIN_MONITOR_INTERVAL_S <= interval <= MAX_MONITOR_INTERVAL_S:
        raise _CliError(
            f"--interval must be {MIN_MONITOR_INTERVAL_S:.0f}.."
            f"{MAX_MONITOR_INTERVAL_S:.0f} seconds"
        )
    cycles = int(args.cycles)
    if not 0 <= cycles <= MAX_MONITOR_CYCLES:
        raise _CliError(f"--cycles must be 0..{MAX_MONITOR_CYCLES} (0 = until interrupted)")
    config = MonitorConfig(
        interval_s=interval,
        timeout_s=float(args.timeout),
        response_delay_factor=int(args.response_delay_factor),
        vlan_id=getattr(args, "vlan", None),
        cycles=cycles,
    )
    interface = _resolve_interface(args.interface)
    quiet = bool(getattr(args, "quiet", False))

    def on_cycle(cycle) -> None:
        if quiet or args.json:
            return
        print(
            f"… cycle {cycle.index + 1}: {cycle.device_count} device(s), "
            f"{len(cycle.changes)} change(s), {cycle.outcome_text}",
            file=sys.stderr,
        )

    with _Session(interface, min_interval_s=args.min_interval) as session:
        run = session.monitor.run(
            config,
            on_cycle=on_cycle,
            progress=_progress(args),
        )
        if args.json:
            _emit_json(run.to_dict())
        else:
            _print_monitor(run)
        return EXIT_FAILED if run.error else EXIT_OK


def _cmd_get(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=False)
    mac = _validated_mac(args.mac)
    selectors = GET_PRESETS[args.preset].selectors
    if args.selector:
        selectors = tuple(_parse_selector(value) for value in args.selector)
    interface = _resolve_interface(args.interface)
    with _Session(interface, min_interval_s=args.min_interval) as session:
        result = session.getter.get(
            mac,
            GetConfig(
                timeout_s=args.timeout,
                vlan_id=args.vlan,
                selectors=selectors,
                min_request_interval_s=args.min_interval,
            ),
            progress=_progress(args),
        )
        _maybe_write_report(args, session, get_result=result)
        if args.json:
            _emit_json(result.to_dict())
        else:
            _print_get(result)
        return _get_exit_code(result)


def _cmd_signal(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=False)
    mac = _validated_mac(args.mac)
    interface = _resolve_interface(args.interface)
    with _Session(interface, min_interval_s=args.min_interval) as session:
        result = session.signal.signal(
            mac,
            timeout_s=args.timeout,
            vlan_id=args.vlan,
            progress=_progress(args),
        )
        _maybe_write_report(args, session, write_result=result)
        if args.json:
            _emit_json(result.to_dict())
        else:
            _print_write(result)
        return _write_exit_code(result)


def _guards_missing(args: argparse.Namespace) -> list[str]:
    return [] if args.confirm else ["--confirm"]


def _identify_target(
    session: _Session,
    mac: str,
    args: argparse.Namespace,
) -> DeviceIdentity | None:
    result = session.discovery.discover(
        DiscoveryConfig(
            timeout_s=min(float(args.timeout), 3.0),
            response_delay_factor=int(
                getattr(args, "response_delay_factor", DEFAULT_RESPONSE_DELAY_FACTOR)
            ),
            vlan_id=args.vlan,
            unicast_mac=mac,
            min_request_interval_s=args.min_interval,
        ),
        progress=_progress(args),
    )
    if result.error:
        raise _CliError(f"Target revalidation failed: {result.error}")
    target = next(
        (device for device in result.devices if device.mac.lower() == mac.lower()),
        None,
    )
    if target is None:
        print(
            "Target did not answer a read-only unicast Identify. "
            "No state-changing frame was transmitted.",
            file=sys.stderr,
        )
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
    return target


def _write_config(args: argparse.Namespace) -> WriteConfig:
    timeout = float(args.timeout)
    return WriteConfig(
        timeout_s=timeout,
        revalidate_timeout_s=timeout,
        verify_timeout_s=timeout,
        vlan_id=args.vlan,
        min_request_interval_s=args.min_interval,
        verify_after_set=True,
    )


def _run_guarded(
    args: argparse.Namespace,
    *,
    spec: OperationSpec,
    kind: str,
    target_mac: str,
    parameters: dict[str, Any],
) -> int:
    _print_operation_spec(
        spec,
        target_mac=target_mac,
        interface=args.interface,
        stream=sys.stderr if args.json else sys.stdout,
    )
    missing = _guards_missing(args)
    if missing:
        message = (
            "Refused: this state-changing command needs "
            + ", ".join(missing)
            + ". Nothing was transmitted."
        )
        print(message, file=sys.stderr)
        if args.json:
            _emit_json(
                {
                    "error": message,
                    "operation": spec.operation_text,
                    "missing_safety_flags": missing,
                    "transmitted": False,
                }
            )
        return EXIT_FAILED

    interface = _resolve_interface(args.interface)
    with _Session(interface, min_interval_s=args.min_interval) as session:
        target = _identify_target(session, target_mac, args)
        if target is None:
            if args.json:
                _emit_json(
                    {
                        "error": (
                            "Target did not answer a read-only unicast Identify; "
                            "no state-changing frame was transmitted."
                        ),
                        "operation": spec.operation_text,
                        "state": "target_unverified",
                        "transmitted": False,
                    }
                )
            return EXIT_UNKNOWN
        confirmation = confirmation_for(
            spec,
            interface_id=session.interface.id,
            interface_name=session.interface.display_name,
            target_mac=target_mac,
            target_identity=identity_text(target),
        )
        request = WriteRequest(
            kind=kind,
            target_mac=target_mac,
            confirmation=confirmation,
            authorization=WriteAuthorization(
                authorization_confirmed=True,
                safe_maintenance_confirmed=True,
            ),
            config=_write_config(args),
            target_name=target.name_of_station,
            **parameters,
        )
        result = session.writer.execute(request, progress=_progress(args))
        if kind in ("reset", "reset_legacy") and result.state == "acknowledged":
            session.writer.post_check(
                result,
                timeout_s=float(args.timeout),
                recheck_window_s=max(0.0, float(getattr(args, "post_check_window", 0.0))),
                progress=_progress(args),
            )
        _maybe_write_report(args, session, write_result=result)
        if args.json:
            _emit_json(result.to_dict())
        else:
            _print_write(result)
        return _write_exit_code(result)


def _cmd_set_name(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=False)
    mac = _validated_mac(args.mac)
    report = validate_station_name(args.name)
    if not report.ok:
        raise _CliError(f"Invalid NameOfStation: {report.summary()}")
    permanent = args.persistence == "permanent"
    return _run_guarded(
        args,
        spec=set_name_spec(args.name, permanent=permanent),
        kind="set_name",
        target_mac=mac,
        parameters={"name": args.name, "permanent": permanent},
    )


def _cmd_set_ip(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=False)
    mac = _validated_mac(args.mac)
    report = validate_ip_suite(args.ip, args.mask, args.gateway)
    if not report.ok:
        raise _CliError(f"Invalid IPv4 suite: {report.summary()}")
    permanent = args.persistence == "permanent"
    return _run_guarded(
        args,
        spec=set_ip_spec(
            args.ip,
            args.mask,
            args.gateway,
            permanent=permanent,
        ),
        kind="set_ip",
        target_mac=mac,
        parameters={
            "ip_address": args.ip,
            "subnet_mask": args.mask,
            "gateway": args.gateway,
            "permanent": permanent,
        },
    )


def _cmd_reset(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=False)
    mac = _validated_mac(args.mac)
    if args.legacy:
        return _run_guarded(
            args,
            spec=legacy_reset_spec(),
            kind="reset_legacy",
            target_mac=mac,
            parameters={},
        )
    return _run_guarded(
        args,
        spec=reset_mode_spec(args.mode),
        kind="reset",
        target_mac=mac,
        parameters={"reset_mode": args.mode},
    )


def _write_test_parameters(args: argparse.Namespace) -> dict[str, dict]:
    """Collect the operator-supplied values for the ``write.*`` test cases."""
    parameters: dict[str, dict] = {}
    if args.name is not None:
        report = validate_station_name(args.name)
        if not report.ok:
            raise _CliError(f"Invalid NameOfStation: {report.summary()}")
        parameters["write.set_name"] = {
            "name": args.name,
            "permanent": args.persistence == "permanent",
        }
    if args.ip is not None or args.mask is not None:
        if args.ip is None or args.mask is None:
            raise _CliError("--ip and --mask must be supplied together")
        report = validate_ip_suite(args.ip, args.mask, args.gateway or "0.0.0.0")
        if not report.ok:
            raise _CliError(f"Invalid IPv4 suite: {report.summary()}")
        parameters["write.set_ip"] = {
            "ip_address": args.ip,
            "subnet_mask": args.mask,
            "gateway": args.gateway or "0.0.0.0",
            "permanent": args.persistence == "permanent",
        }
    if args.reset_mode is not None:
        parameters["write.reset"] = {"reset_mode": int(args.reset_mode)}
    return parameters


def _cmd_tests(args: argparse.Namespace) -> int:
    _validate_common(args, discovery=True)
    if args.list:
        print(f"{'ID':<32}  {'Live':<5}  {'Default':<7}  Name")
        for case in TEST_CASES:
            print(
                f"{case.test_id:<32}  {str(case.live):<5}  "
                f"{str(case.default_enabled):<7}  {case.name}"
            )
        return EXIT_OK

    by_id = {case.test_id: case for case in TEST_CASES}
    if args.select:
        unknown = sorted(set(args.select) - set(by_id))
        if unknown:
            raise _CliError("Unknown test id(s): " + ", ".join(unknown))
        selected = set(args.select)
    else:
        selected = {
            case.test_id
            for case in TEST_CASES
            if case.implemented
            and (
                case.default_enabled
                or (args.include_writes and case.test_id.startswith("write."))
            )
        }
    guarded = sorted(test_id for test_id in selected if test_id.startswith("write."))
    if guarded and not args.include_writes:
        raise _CliError(
            "This selection contains state-changing test(s): "
            + ", ".join(guarded)
            + ". Pass --include-writes with --confirm and --mac to run them, or use "
            "'dcp-cli set-name', 'set-ip' or 'reset'."
        )

    target: DeviceIdentity | None = None
    write_authorizations: dict[str, WriteAuthorization] = {}
    write_parameters: dict[str, dict] = {}
    if guarded:
        if not args.confirm:
            raise _CliError("--include-writes requires --confirm. Nothing was transmitted.")
        if not args.mac:
            raise _CliError(
                "--include-writes requires --mac: the write tests target exactly one "
                "declared device under test. Nothing was transmitted."
            )
        write_parameters = _write_test_parameters(args)
        write_authorizations = {
            test_id: WriteAuthorization(
                authorization_confirmed=True,
                safe_maintenance_confirmed=True,
            )
            for test_id in guarded
        }

    interface = _resolve_interface(args.interface)
    config = _app_config(args, interface)
    with _Session(interface, min_interval_s=args.min_interval) as session:
        if guarded:
            target = _identify_target(session, _validated_mac(args.mac), args)
            if target is None:
                raise _CliError(
                    "The declared device under test did not answer a unicast Identify; "
                    "no state-changing frame was transmitted."
                )
        runner = TestRunner(
            session.transport,
            config,
            event_log=session.logger,
            discovery_service=session.discovery,
            get_service=session.getter,
            write_service=session.writer,
            safety_gate=session.writer.safety,
            target=target,
            write_authorizations=write_authorizations,
            write_parameters=write_parameters,
        )
        results = runner.run(
            selected,
            progress=None
            if args.quiet
            else (lambda index, total, name: print(f"[{index}/{total}] {name}", file=sys.stderr)),
        )
        summary = summarize_statuses(results)
        _maybe_write_report(args, session, test_results=results)
        if args.json:
            _emit_json({"summary": summary, "results": [r.to_dict() for r in results]})
        else:
            print(f"{'STATUS':<12}  {'ID':<32}  Name")
            for result in results:
                print(f"{result.status:<12}  {result.test_id:<32}  {result.name}")
                if result.detail:
                    print(f"              {result.detail}")
            print(
                "Summary: "
                + ", ".join(f"{key}={value}" for key, value in summary.items())
            )
        if summary.get("failed"):
            return EXIT_FAILED
        if summary.get("inconclusive"):
            return EXIT_UNKNOWN
        return EXIT_OK


def _cmd_pcap(args: argparse.Namespace) -> int:
    try:
        frames = analyze_pcap(args.path)
    except (PcapError, OSError) as exc:
        raise _CliError(f"Could not read {args.path}: {exc}") from exc
    if args.dcp_only:
        frames = [frame for frame in frames if frame.parsed is not None and frame.parsed.is_dcp]
    if args.json:
        _emit_json(
            [
                {
                    "timestamp": iso_utc(frame.timestamp),
                    "interface": frame.interface_id,
                    "direction": frame.direction,
                    "summary": frame.summary,
                    "frame": frame.parsed.to_dict() if frame.parsed is not None else None,
                }
                for frame in frames
            ]
        )
        return EXIT_OK
    print(f"{len(frames)} frame(s) from {args.path}")
    for index, frame in enumerate(frames, start=1):
        parsed = frame.parsed
        details = ""
        if parsed is not None and parsed.is_dcp:
            details = (
                f" src={parsed.src_mac} dst={parsed.dst_mac} "
                f"xid=0x{(parsed.xid or 0):08x}"
            )
        print(f"{index:>5}  {iso_utc(frame.timestamp)}  {frame.summary}{details}")
        if args.hex:
            print(f"       {frame.raw.hex()}")
    return EXIT_OK


# -------------------------------------------------------------------- parser
def _add_interface_arguments(
    parser: argparse.ArgumentParser,
    *,
    timeout: float,
    with_delay_factor: bool = True,
    with_report: bool = True,
) -> None:
    parser.add_argument(
        "-i",
        "--interface",
        default="demo",
        help="Interface id or name; 'demo' selects the offline mock segment (default: demo)",
    )
    parser.add_argument("--vlan", type=int, default=None, help="Optional 802.1Q VLAN ID 1..4094")
    parser.add_argument(
        "--timeout", type=float, default=timeout, help=f"Response timeout in seconds (default: {timeout})"
    )
    if with_delay_factor:
        parser.add_argument(
            "--response-delay-factor",
            type=int,
            default=DEFAULT_RESPONSE_DELAY_FACTOR,
            help=(
                "DCP ResponseDelayFactor for Identify requests in 10 ms units "
                f"(default: {DEFAULT_RESPONSE_DELAY_FACTOR})"
            ),
        )
    parser.add_argument(
        "--min-interval",
        type=float,
        default=DEFAULT_MIN_REQUEST_INTERVAL_S,
        help=(
            "Minimum interval between DCP requests in seconds "
            f"(default: {DEFAULT_MIN_REQUEST_INTERVAL_S})"
        ),
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress messages")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    if with_report:
        parser.add_argument(
            "--report",
            metavar="PATH",
            help="Write a JSON report (or escaped HTML when PATH ends in .html/.htm)",
        )


def _add_guard_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--confirm",
        action="store_true",
        help=(
            "Confirm authorization for this state change and that the equipment is "
            "in a safe maintenance state (required)"
        ),
    )
    parser.add_argument(
        "--post-check-window",
        type=float,
        default=DEFAULT_POST_CHECK_WINDOW_S,
        metavar="SECONDS",
        help=(
            "After an acknowledged reset, keep polling the read-only post-check "
            "Identify for this long before reporting no response "
            f"(default: {DEFAULT_POST_CHECK_WINDOW_S:.0f} s)"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dcp-cli",
        description=(
            "Headless PROFINET DCP discovery, Get, LED Signal, confirmed "
            "Set/Reset, functional checks and offline PCAP analysis. "
            "State-changing commands require --confirm and send one "
            "unicast frame without retry."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    interfaces = subparsers.add_parser("interfaces", help="List local interfaces")
    interfaces.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    interfaces.add_argument(
        "--readiness",
        action="store_true",
        help="Also report raw-capture readiness/privileges for each interface",
    )
    interfaces.set_defaults(handler=_cmd_interfaces)

    discover = subparsers.add_parser(
        "discover", help="Send one Identify request and list responding devices"
    )
    _add_interface_arguments(discover, timeout=3.0)
    discover.add_argument(
        "--unicast",
        metavar="MAC",
        help="Send unicast Identify to one device instead of multicast Identify-All",
    )
    discover.add_argument(
        "--name",
        metavar="NAME",
        help="Filter by exact NameOfStation (case-sensitive; one 02/02 block)",
    )
    discover.set_defaults(handler=_cmd_discover)

    inventory = subparsers.add_parser(
        "inventory",
        help=(
            "Discover devices and export an inventory CSV; optionally compare a plan "
            "(read-only)"
        ),
    )
    _add_interface_arguments(inventory, timeout=3.0)
    inventory.add_argument(
        "--name",
        metavar="NAME",
        help="Filter by exact NameOfStation (case-sensitive; one 02/02 block)",
    )
    inventory.add_argument(
        "--csv",
        metavar="PATH",
        help="Write the discovered devices to this CSV inventory path",
    )
    inventory.add_argument(
        "--plan",
        metavar="PATH",
        help=(
            "Compare against a plan CSV with mac/name_of_station/ip_address/"
            "subnet_mask/gateway columns"
        ),
    )
    inventory.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when the plan comparison reports any finding",
    )
    inventory.set_defaults(handler=_cmd_inventory)

    monitor = subparsers.add_parser(
        "monitor",
        help="Repeat Identify at an interval and report identity changes (read-only)",
    )
    _add_interface_arguments(monitor, timeout=3.0, with_report=False)
    monitor.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Minimum seconds between Identify cycles (default: 5.0)",
    )
    monitor.add_argument(
        "--cycles",
        type=int,
        default=1,
        help="Number of Identify cycles; 0 runs until interrupted (default: 1)",
    )
    monitor.set_defaults(handler=_cmd_monitor)

    get = subparsers.add_parser("get", help="Read DCP blocks from one device (read-only)")
    _add_interface_arguments(get, timeout=2.0)
    get.add_argument("--mac", required=True, metavar="MAC", help="Target device MAC")
    get.add_argument(
        "--preset",
        choices=sorted(GET_PRESETS),
        default="identity",
        help="Selector preset (default: identity)",
    )
    get.add_argument(
        "--selector",
        action="append",
        metavar="OPTION/SUBOPTION",
        help="Explicit selector such as 0x02/0x02; may be repeated (overrides --preset)",
    )
    get.set_defaults(handler=_cmd_get)

    signal = subparsers.add_parser(
        "signal", help="Flash the identification LED (05/03; one unicast frame, unguarded)"
    )
    _add_interface_arguments(signal, timeout=2.0, with_delay_factor=False)
    signal.add_argument("--mac", required=True, metavar="MAC", help="Target device MAC")
    signal.set_defaults(handler=_cmd_signal)

    set_name = subparsers.add_parser(
        "set-name", help="Set NameOfStation (--confirm)"
    )
    _add_interface_arguments(set_name, timeout=2.0)
    set_name.add_argument("--mac", required=True, metavar="MAC", help="Target device MAC")
    set_name.add_argument(
        "--name",
        required=True,
        metavar="NAME",
        help="New NameOfStation; pass an empty string to clear the name",
    )
    set_name.add_argument(
        "--persistence",
        choices=("permanent", "temporary"),
        default="permanent",
        help="BlockQualifier persistence (default: permanent)",
    )
    _add_guard_arguments(set_name)
    set_name.set_defaults(handler=_cmd_set_name)

    set_ip = subparsers.add_parser(
        "set-ip", help="Set IP parameters (--confirm)"
    )
    _add_interface_arguments(set_ip, timeout=2.0)
    set_ip.add_argument("--mac", required=True, metavar="MAC", help="Target device MAC")
    set_ip.add_argument("--ip", required=True, metavar="ADDRESS", help="New IPv4 address")
    set_ip.add_argument("--mask", required=True, metavar="MASK", help="Subnet mask")
    set_ip.add_argument(
        "--gateway", default="0.0.0.0", metavar="ADDRESS", help="Gateway (default: 0.0.0.0)"
    )
    set_ip.add_argument(
        "--persistence",
        choices=("permanent", "temporary"),
        default="permanent",
        help="BlockQualifier persistence (default: permanent)",
    )
    _add_guard_arguments(set_ip)
    set_ip.set_defaults(handler=_cmd_set_ip)

    reset = subparsers.add_parser(
        "reset", help="Reset: RTFS modes 1/2/3/4/8/9 or legacy 05/05 (--confirm)"
    )
    _add_interface_arguments(reset, timeout=2.0)
    reset.add_argument("--mac", required=True, metavar="MAC", help="Target device MAC")
    variant = reset.add_mutually_exclusive_group(required=True)
    variant.add_argument(
        "--mode",
        type=int,
        choices=sorted(SUPPORTED_RESET_MODES),
        help="ResetToFactorySettings mode (verified modes only)",
    )
    variant.add_argument(
        "--legacy",
        action="store_true",
        help="Legacy FactoryReset 05/05 (full reset, no mode field)",
    )
    _add_guard_arguments(reset)
    reset.set_defaults(handler=_cmd_reset)

    tests = subparsers.add_parser(
        "tests",
        help="Run functional checks; write.* needs --include-writes --confirm --mac",
    )
    _add_interface_arguments(tests, timeout=3.0)
    tests.add_argument("--list", action="store_true", help="List available test cases and exit")
    tests.add_argument(
        "--select",
        action="append",
        metavar="ID",
        help="Run only the given test id; may be repeated",
    )
    tests.add_argument(
        "--include-writes",
        action="store_true",
        help=(
            "Add the write.* cases to the default selection and allow them to run "
            "against the --mac target (requires --confirm)"
        ),
    )
    tests.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm the state-changing test run (required with --include-writes)",
    )
    tests.add_argument(
        "--mac", metavar="MAC", help="Declared device under test for write.* cases"
    )
    tests.add_argument(
        "--name", metavar="NAME", help="NameOfStation value for write.set_name"
    )
    tests.add_argument(
        "--persistence",
        choices=("permanent", "temporary"),
        default="permanent",
        help="BlockQualifier persistence for write.set_name/write.set_ip",
    )
    tests.add_argument(
        "--ip", metavar="ADDRESS", help="IPv4 address for write.set_ip"
    )
    tests.add_argument(
        "--mask", metavar="MASK", help="Subnet mask for write.set_ip"
    )
    tests.add_argument(
        "--gateway",
        default="0.0.0.0",
        metavar="ADDRESS",
        help="Gateway for write.set_ip (default: 0.0.0.0)",
    )
    tests.add_argument(
        "--reset-mode",
        type=int,
        choices=sorted(SUPPORTED_RESET_MODES),
        help="ResetToFactorySettings mode for write.reset",
    )
    tests.set_defaults(handler=_cmd_tests)

    pcap = subparsers.add_parser("pcap", help="Decode an offline Ethernet PCAP file")
    pcap.add_argument("path", metavar="PATH", help="Classic Ethernet pcap file")
    pcap.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    pcap.add_argument("--dcp-only", action="store_true", help="Only print DCP frames")
    pcap.add_argument("--hex", action="store_true", help="Print raw frame bytes as hex")
    pcap.set_defaults(handler=_cmd_pcap)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = args.handler
    try:
        return int(handler(args))
    except _CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except TransportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
