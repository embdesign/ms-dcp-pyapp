"""Functional test runner: read-only checks plus optional guarded writes.

Read-only tests never change equipment. Optional Name/IP Set and Reset tests
require configuration mode, a selected target, and a separate per-operation
confirmation
supplied before the run. No fuzzing is sent to live equipment, no continuous
scanning is performed, and every state-changing request is single-shot.
"""

from __future__ import annotations

import struct
import threading
import time
from collections.abc import Callable

from ..codec import (
    build_get_request,
    classify_set_response,
    encode_block,
    extract_device_identity,
    parse_frame,
)
from ..config import AppConfig
from ..constants import (
    ETHERTYPE_PROFINET,
    ControlSubOption,
    FrameId,
    Option,
    ServiceId,
    ServiceType,
)
from ..fixtures import get_fixture
from ..logging_setup import EventLogger
from ..mock import MockNetwork, MockTransport, default_mock_devices
from ..model import DeviceIdentity, TestResult, utc_now
from ..operations import (
    OperationSpec,
    confirmation_for,
    reset_mode_spec,
    set_ip_spec,
    set_name_spec,
)
from ..pcap_io import analyze_pcap, write_pcap
from ..safety import SafetyGate
from ..services.discovery import DiscoveryConfig, DiscoveryService
from ..services.get import GET_PRESETS, GetConfig, GetService
from ..services.write import (
    WriteAuthorization,
    WriteConfig,
    WriteRequest,
    WriteService,
    identity_text,
)
from ..transport.base import DcpTransport
from ..validation import validate_ip_suite, validate_station_name
from .cases import TEST_CASES, TestCase

ProgressCallback = Callable[[int, int, str], None]


class TestRunner:
    __test__ = False

    def __init__(
        self,
        transport: DcpTransport,
        config: AppConfig,
        *,
        event_log: EventLogger | None = None,
        discovery_service: DiscoveryService | None = None,
        get_service: GetService | None = None,
        write_service: WriteService | None = None,
        safety_gate: SafetyGate | None = None,
        target: DeviceIdentity | None = None,
        write_authorizations: dict[str, WriteAuthorization] | None = None,
        write_parameters: dict[str, dict] | None = None,
    ) -> None:
        self.transport = transport
        self.config = config
        self.event_log = event_log
        self.discovery_service = discovery_service
        self.get_service = get_service
        self.write_service = write_service
        self.safety_gate = safety_gate or SafetyGate()
        self.target = target
        self.write_authorizations = dict(write_authorizations or {})
        self.write_parameters = dict(write_parameters or {})
        self.latest_discovery = None
        self._callback_installed = (
            discovery_service is not None
            and get_service is not None
            and write_service is not None
        )

    def _ensure_services(self) -> tuple[DiscoveryService, GetService, WriteService]:
        def event_log(event: str, message: str, detail: dict) -> None:
            if self.event_log:
                self.event_log.info(event, message, detail)

        if self.discovery_service is None:
            self.discovery_service = DiscoveryService(self.transport, event_log=event_log)
        if self.get_service is None:
            self.get_service = GetService(
                self.transport,
                limiter=self.discovery_service.limiter,
                event_log=event_log,
            )
        if self.write_service is None:
            self.write_service = WriteService(
                self.transport,
                discovery_service=self.discovery_service,
                get_service=self.get_service,
                safety=self.safety_gate,
                limiter=self.discovery_service.limiter,
                event_log=event_log,
            )
        if not self._callback_installed:
            discovery = self.discovery_service
            getter = self.get_service
            writer = self.write_service
            self.transport.set_frame_callback(
                lambda raw, ts, direction: (
                    discovery.process_frame(raw, ts, direction),
                    getter.process_frame(raw, ts, direction),
                    writer.process_frame(raw, ts, direction),
                )
            )
            self._callback_installed = True
        return self.discovery_service, self.get_service, self.write_service

    def _discovery(self) -> DiscoveryService:
        return self._ensure_services()[0]

    def _getter(self) -> GetService:
        return self._ensure_services()[1]

    def _writer(self) -> WriteService:
        return self._ensure_services()[2]

    def list_tests(self) -> list[TestCase]:
        return list(TEST_CASES)

    def run(
        self,
        selected_ids: set[str] | None = None,
        *,
        cancel_event: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> list[TestResult]:
        cancel_event = cancel_event or threading.Event()
        cases = [
            case
            for case in TEST_CASES
            if selected_ids is None or case.test_id in selected_ids
        ]
        results: list[TestResult] = []
        total = len(cases)
        for index, case in enumerate(cases, start=1):
            if progress:
                progress(index, total, case.name)
            if cancel_event.is_set():
                break
            results.append(self._execute(case, cancel_event))
        return results

    def _execute(self, case: TestCase, cancel_event: threading.Event) -> TestResult:
        started = utc_now()
        t0 = time.monotonic()
        try:
            if not case.implemented:
                result = TestResult(
                    test_id=case.test_id,
                    name=case.name,
                    category=case.category,
                    status="skipped",
                    detail=(
                        "Not implemented in this build. Disabled by design; it "
                        "cannot be selected and no DCP request is transmitted."
                    ),
                    started_at=started,
                    duration_ms=0.0,
                    live=case.live,
                )
            else:
                handler = getattr(self, f"_test_{case.test_id.replace('.', '_')}")
                result = handler(case, cancel_event)
        except Exception as exc:
            result = TestResult(
                test_id=case.test_id,
                name=case.name,
                category=case.category,
                status="failed",
                detail=f"Test raised {type(exc).__name__}: {exc}",
                started_at=started,
                duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
                live=case.live,
            )
        result.duration_ms = round((time.monotonic() - t0) * 1000.0, 3)
        if self.event_log:
            self.event_log.log(
                "INFO" if result.status == "passed" else "WARNING",
                "test.result",
                f"{case.test_id}: {result.status}",
                result.to_dict(),
            )
        return result

    # ------------------------------------------------------------------ tests
    def _result(
        self,
        case: TestCase,
        status: str,
        detail: str,
        *,
        started=None,
        evidence: dict | None = None,
        warnings: list[str] | None = None,
    ) -> TestResult:
        return TestResult(
            test_id=case.test_id,
            name=case.name,
            category=case.category,
            status=status,
            detail=detail,
            started_at=started or utc_now(),
            duration_ms=0.0,
            live=case.live,
            evidence=evidence or {},
            warnings=warnings or [],
        )

    def _ensure_capture(self) -> tuple[bool, str]:
        if self.transport.is_capturing:
            return True, "Capture already running"
        try:
            self.transport.start_capture()
            return True, "Capture started"
        except Exception as exc:
            return False, str(exc)

    def _test_env_interface(self, case, cancel_event) -> TestResult:
        iface = self.transport.interface
        evidence = {
            "name": iface.name,
            "id": iface.id,
            "mac": iface.mac,
            "link": iface.link_text,
            "kind": iface.kind,
        }
        if not iface.mac:
            return self._result(case, "failed", "Interface has no MAC address", evidence=evidence)
        if iface.is_loopback:
            return self._result(
                case,
                "inconclusive",
                "Loopback interface cannot reach a physical PROFINET segment",
                evidence=evidence,
            )
        if iface.is_up is False:
            return self._result(
                case, "inconclusive", "Interface link is down", evidence=evidence
            )
        return self._result(
            case, "passed", f"Interface {iface.name} ({iface.mac}) is usable", evidence=evidence
        )

    def _test_env_readiness(self, case, cancel_event) -> TestResult:
        readiness = self.transport.readiness()
        evidence = readiness.to_dict()
        if readiness.ready:
            return self._result(case, "passed", readiness.message, evidence=evidence)
        return self._result(
            case,
            "failed",
            readiness.message,
            evidence=evidence,
            warnings=readiness.hints,
        )

    def _test_env_capture(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        if not self.transport.is_capturing:
            return self._result(case, "failed", "Capture did not enter the running state")
        return self._result(
            case,
            "passed",
            f"{message}; passive capture is running on {self.transport.interface.name}",
            evidence={"interface": self.transport.interface.id},
        )

    def _test_parser_fixture_decode(self, case, cancel_event) -> TestResult:
        raw = get_fixture("identify_response_named")
        frame = parse_frame(raw, interface_id="fixture")
        identity = extract_device_identity(frame)
        if identity is None:
            return self._result(
                case, "failed", "Fixture was not recognized as an Identify response"
            )
        checks = {
            "name": identity.name_of_station == "line-01.conveyor",
            "ip": identity.ip_address == "192.0.2.11",
            "mask": identity.subnet_mask == "255.255.255.0",
            "gateway": identity.gateway == "192.0.2.1",
            "vendor_id": identity.vendor_id == 0x002A,
            "device_id": identity.device_id == 0x0101,
            "role": identity.device_role_flags == 0x01,
        }
        evidence = {"checks": checks, "identity": identity.to_dict()}
        if all(checks.values()):
            return self._result(case, "passed", "All fixture fields decoded correctly", evidence=evidence)
        failed = [name for name, ok in checks.items() if not ok]
        return self._result(
            case, "failed", "Fixture field mismatch: " + ", ".join(failed), evidence=evidence
        )

    def _test_parser_malformed(self, case, cancel_event) -> TestResult:
        outcomes = {}
        for name in (
            "identify_response_truncated",
            "identify_response_bad_block_length",
            "profinet_rt_non_dcp",
        ):
            try:
                frame = parse_frame(get_fixture(name))
                outcomes[name] = {
                    "kind": frame.kind,
                    "warnings": frame.warnings,
                    "blocks": len(frame.blocks),
                }
            except Exception as exc:
                return self._result(
                    case,
                    "failed",
                    f"Parser raised on {name}: {type(exc).__name__}: {exc}",
                    evidence=outcomes,
                )
        truncated = outcomes["identify_response_bad_block_length"]
        if not truncated["warnings"]:
            return self._result(
                case,
                "failed",
                "Malformed block length did not produce a warning",
                evidence=outcomes,
            )
        if outcomes["profinet_rt_non_dcp"]["kind"] != "profinet_other":
            return self._result(
                case,
                "failed",
                "Non-DCP PROFINET frame was not distinguished from DCP",
                evidence=outcomes,
            )
        return self._result(
            case,
            "passed",
            "Truncated/malformed frames parsed defensively without exceptions",
            evidence=outcomes,
        )

    def _test_parser_pcap_roundtrip(self, case, cancel_event) -> TestResult:
        import tempfile
        from pathlib import Path

        from ..model import CapturedFrame

        raw = get_fixture("identify_response_named")
        timestamp = utc_now()
        frame = CapturedFrame(
            timestamp=timestamp,
            interface_id="fixture",
            direction="rx",
            raw=raw,
            parsed=parse_frame(raw, captured_at=timestamp),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "roundtrip.pcap"
            count = write_pcap(path, [frame])
            records = analyze_pcap(path)
        if count != 1 or len(records) != 1 or records[0].raw != raw:
            return self._result(case, "failed", "PCAP roundtrip byte comparison failed")
        return self._result(
            case,
            "passed",
            "PCAP write/read roundtrip preserved the frame",
            evidence={
                "records": len(records),
                "bytes": len(raw),
                "timestamp_utc": records[0].timestamp.isoformat(),
            },
        )

    def _test_parser_block_errors(self, case, cancel_event) -> TestResult:
        def mac(value: str) -> bytes:
            return bytes(int(part, 16) for part in value.split(":"))

        outcomes = {}
        for code in range(0, 8):
            payload = encode_block(
                int(Option.CONTROL),
                int(ControlSubOption.RESPONSE),
                value=bytes([int(Option.DEVICE_PROPERTIES), 0x02, code]),
            )
            header = (
                bytes([int(ServiceId.SET), int(ServiceType.RESPONSE_SUCCESS)])
                + struct.pack("!I", 0x01020304)
                + struct.pack("!H", 0)
                + struct.pack("!H", len(payload))
            )
            raw = (
                mac("02:00:00:00:00:01")
                + mac("02:00:00:00:00:11")
                + struct.pack("!H", ETHERTYPE_PROFINET)
                + struct.pack("!H", int(FrameId.GET_SET))
                + header
                + payload
            )
            verdict, error, text = classify_set_response(parse_frame(raw))
            outcomes[f"0x{code:02x}"] = {"verdict": verdict, "error": error, "text": text}
        failures = []
        if outcomes["0x00"]["verdict"] != "acknowledged":
            failures.append("error 0x00 was not acknowledged")
        for code in range(1, 8):
            entry = outcomes[f"0x{code:02x}"]
            if entry["verdict"] != "rejected" or entry["error"] != code:
                failures.append(f"error 0x{code:02x} was not decoded as rejected")
            if "Reserved block error" in entry["text"]:
                failures.append(f"error 0x{code:02x} has no documented text")
        if failures:
            return self._result(case, "failed", "; ".join(failures), evidence=outcomes)
        return self._result(
            case,
            "passed",
            "All documented Control/Response block errors decoded",
            evidence=outcomes,
        )

    def _test_protocol_transaction_matching(self, case, cancel_event) -> TestResult:
        network = MockNetwork(default_mock_devices()[:1])
        transport = MockTransport(network)
        transport.start_capture()
        discovery = DiscoveryService(transport)
        seen_request: list[tuple[bytes, object]] = []

        def listener(raw: bytes, ts, direction: str) -> None:
            if direction == "tx":
                request = parse_frame(raw)
                seen_request.append((raw, request))
                correct = network.build_identify_response(network.devices[0], request)
                # Corrupt the response Xid (DCP header Xid is at offset 18..21).
                wrong = correct[:18] + b"\xde\xad\xbe\xef" + correct[22:]
                transport.feed(wrong)
                transport.feed(correct)
            else:
                discovery.process_frame(raw, ts, direction)

        transport.set_frame_callback(listener)
        try:
            result = discovery.discover(DiscoveryConfig(timeout_s=0.5))
        finally:
            transport.close()
        evidence = result.to_dict()
        if result.unmatched_responses != 1:
            return self._result(
                case,
                "failed",
                f"Expected 1 unrelated response, observed {result.unmatched_responses}",
                evidence=evidence,
            )
        if len(result.devices) != 1:
            return self._result(
                case, "failed", "Matching response was not attributed to a device", evidence=evidence
            )
        return self._result(
            case,
            "passed",
            "Wrong-Xid response ignored; matching response correlated correctly",
            evidence=evidence,
        )

    def _test_protocol_get_offline(self, case, cancel_event) -> TestResult:
        device = default_mock_devices()[0]
        network = MockNetwork([device])
        request = build_get_request(
            "02:00:00:00:00:01",
            device.mac,
            0xAABBCCDD,
            [
                (int(Option.IP), 0x02),
                (int(Option.DEVICE_PROPERTIES), 0x02),
                (int(Option.DEVICE_PROPERTIES), 0x03),
            ],
        )
        responses = network.handle_request(request)
        if not responses:
            return self._result(case, "failed", "Mock network returned no Get response")
        frame = parse_frame(responses[0])
        blocks = {(b.option, b.suboption): b for b in frame.blocks}
        checks = {
            "service": frame.service_id == int(ServiceId.GET)
            and frame.service_type == int(ServiceType.RESPONSE_SUCCESS),
            "ip": len(blocks.get((1, 2)).value) == 12 if blocks.get((1, 2)) else False,
            "name": blocks.get((2, 2)).value == b"line-01.conveyor"
            if blocks.get((2, 2))
            else False,
            "device_id": blocks.get((2, 3)).value == b"\x00\x2a\x01\x01"
            if blocks.get((2, 3))
            else False,
        }
        if all(checks.values()):
            return self._result(
                case,
                "passed",
                "Multi-block Get request/response decoded correctly (offline mock)",
                evidence={"checks": checks, "response_hex": responses[0].hex()},
            )
        return self._result(
            case,
            "failed",
            "Get decode mismatch: " + ", ".join(k for k, v in checks.items() if not v),
            evidence={"checks": checks},
        )

    def _test_protocol_identify_discovery(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        discovery = self._discovery()
        config = DiscoveryConfig(
            timeout_s=self.config.timeout_s,
            response_delay_factor=self.config.response_delay_factor,
            vlan_id=self.config.vlan_id,
            min_request_interval_s=self.config.min_request_interval_s,
        )
        result = discovery.discover(config, cancel_event=cancel_event)
        self.latest_discovery = result
        evidence = result.to_dict()
        if result.error:
            return self._result(case, "failed", result.error, evidence=evidence)
        if result.cancelled:
            return self._result(case, "skipped", "Cancelled by user", evidence=evidence)
        in_window = [
            d
            for d in result.devices
            if not any("after the configured timeout" in w for w in d.warnings)
        ]
        if not in_window:
            return self._result(
                case,
                "inconclusive",
                "No matching response observed. Absence is not proof that no device exists.",
                evidence=evidence,
                warnings=result.warnings,
            )
        return self._result(
            case,
            "passed",
            f"{len(in_window)} device(s) responded to Identify",
            evidence=evidence,
            warnings=result.warnings,
        )

    def _test_protocol_unicast_identify(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        discovery = self._discovery()
        base_config = DiscoveryConfig(
            timeout_s=self.config.timeout_s,
            response_delay_factor=self.config.response_delay_factor,
            vlan_id=self.config.vlan_id,
            min_request_interval_s=self.config.min_request_interval_s,
        )
        if self.latest_discovery is None or not self.latest_discovery.devices:
            self.latest_discovery = discovery.discover(base_config, cancel_event=cancel_event)
        if self.latest_discovery.cancelled:
            return self._result(case, "skipped", "Cancelled by user")
        if not self.latest_discovery.devices:
            return self._result(
                case,
                "inconclusive",
                "No device is available for a unicast Identify; run multicast discovery first.",
                evidence={"multicast": self.latest_discovery.to_dict()},
            )
        target = self.latest_discovery.devices[0]
        unicast_config = DiscoveryConfig(
            timeout_s=min(self.config.timeout_s, 3.0),
            response_delay_factor=self.config.response_delay_factor,
            vlan_id=self.config.vlan_id,
            unicast_mac=target.mac,
            min_request_interval_s=self.config.min_request_interval_s,
        )
        result = discovery.discover(unicast_config, cancel_event=cancel_event)
        evidence = {"target": target.mac, "result": result.to_dict()}
        in_window = [
            d
            for d in result.devices
            if not any("after the configured timeout" in w for w in d.warnings)
        ]
        if not in_window:
            return self._result(
                case,
                "inconclusive",
                "The device did not answer unicast Identify. This is device-dependent and "
                "is not evidence that the tool or device is broken.",
                evidence=evidence,
                warnings=result.warnings,
            )
        return self._result(
            case,
            "passed",
            f"Device {target.mac} answered unicast Identify",
            evidence=evidence,
        )

    def _test_protocol_get_live(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        discovery, getter, _ = self._ensure_services()
        base_config = DiscoveryConfig(
            timeout_s=self.config.timeout_s,
            response_delay_factor=self.config.response_delay_factor,
            vlan_id=self.config.vlan_id,
            min_request_interval_s=self.config.min_request_interval_s,
        )
        if self.latest_discovery is None or not self.latest_discovery.devices:
            self.latest_discovery = discovery.discover(base_config, cancel_event=cancel_event)
        if self.latest_discovery.cancelled:
            return self._result(case, "skipped", "Cancelled during discovery")
        if not self.latest_discovery.devices:
            return self._result(
                case,
                "inconclusive",
                "No device is available for a live Get; discovery observed no response.",
                evidence={"discovery": self.latest_discovery.to_dict()},
            )
        target = self.latest_discovery.devices[0]
        result = getter.get(
            target.mac,
            GetConfig(
                timeout_s=min(self.config.timeout_s, 3.0),
                vlan_id=self.config.vlan_id,
                selectors=GET_PRESETS["identity"].selectors,
                min_request_interval_s=self.config.min_request_interval_s,
            ),
            cancel_event=cancel_event,
        )
        evidence = {"target": target.mac, "get": result.to_dict()}
        if result.state == "cancelled":
            return self._result(case, "skipped", "Cancelled during Get", evidence=evidence)
        if result.state == "no_response":
            return self._result(
                case,
                "inconclusive",
                "No matching Get response was observed. This does not prove that the "
                "device does not support Get.",
                evidence=evidence,
                warnings=result.warnings,
            )
        if result.state == "service_not_supported":
            return self._result(
                case,
                "inconclusive",
                "The device reports DCP Get as unsupported.",
                evidence=evidence,
                warnings=result.warnings,
            )
        if result.block_errors:
            return self._result(
                case,
                "inconclusive",
                f"{len(result.block_errors)} requested block(s) were rejected; "
                "this is reported as a DCP block error, not a transport failure.",
                evidence=evidence,
                warnings=result.warnings,
            )
        if not result.blocks:
            return self._result(
                case,
                "failed",
                "Get response contained no blocks despite a success ServiceType.",
                evidence=evidence,
            )
        checks = {
            "target": result.identity is not None and result.identity.mac.lower() == target.mac.lower(),
            "blocks": len(result.blocks) > 0,
            "no_block_errors": not result.block_errors,
        }
        if result.identity is not None:
            if target.name_of_station is not None:
                checks["name_matches"] = result.identity.name_of_station == target.name_of_station
            if target.ip_address is not None:
                checks["ip_matches"] = result.identity.ip_address == target.ip_address
            if target.vendor_id is not None:
                checks["device_id_matches"] = (
                    result.identity.vendor_id == target.vendor_id
                    and result.identity.device_id == target.device_id
                )
        evidence["checks"] = checks
        if all(checks.values()):
            return self._result(
                case,
                "passed",
                f"Read-only Get received {len(result.blocks)} block(s) from {target.mac}",
                evidence=evidence,
                warnings=result.warnings,
            )
        return self._result(
            case,
            "inconclusive",
            "Get responded, but not all identity fields matched the earlier discovery: "
            + ", ".join(k for k, v in checks.items() if not v),
            evidence=evidence,
            warnings=result.warnings,
        )

    def _test_protocol_identity_before_after(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        discovery = self._discovery()
        config = DiscoveryConfig(
            timeout_s=self.config.timeout_s,
            response_delay_factor=self.config.response_delay_factor,
            vlan_id=self.config.vlan_id,
            min_request_interval_s=self.config.min_request_interval_s,
        )
        before = discovery.discover(config, cancel_event=cancel_event)
        if before.cancelled:
            return self._result(case, "skipped", "Cancelled before the second discovery")
        after = discovery.discover(config, cancel_event=cancel_event)
        if after.cancelled:
            return self._result(case, "skipped", "Cancelled before the comparison")
        before_map = {
            d.mac: {
                "name": d.name_of_station,
                "ip": d.ip_address,
                "mask": d.subnet_mask,
                "gateway": d.gateway,
                "vendor_id": d.vendor_id,
                "device_id": d.device_id,
                "role": d.device_role_flags,
            }
            for d in before.devices
        }
        after_map = {
            d.mac: {
                "name": d.name_of_station,
                "ip": d.ip_address,
                "mask": d.subnet_mask,
                "gateway": d.gateway,
                "vendor_id": d.vendor_id,
                "device_id": d.device_id,
                "role": d.device_role_flags,
            }
            for d in after.devices
        }
        evidence = {"before": before_map, "after": after_map}
        if not before_map or not after_map:
            return self._result(
                case,
                "inconclusive",
                "A device did not respond in both read-only observations.",
                evidence=evidence,
            )
        changes = {
            mac: {"before": before_map.get(mac), "after": after_map.get(mac)}
            for mac in sorted(set(before_map) | set(after_map))
            if before_map.get(mac) != after_map.get(mac)
        }
        evidence["changes"] = changes
        if changes:
            return self._result(
                case,
                "inconclusive",
                f"Identity changed for {len(changes)} device(s) between two read-only "
                "observations (no configuration was performed by this tool).",
                evidence=evidence,
            )
        return self._result(
            case,
            "passed",
            f"Identity stable for {len(before_map)} device(s) across two paced observations",
            evidence=evidence,
        )

    def _test_protocol_repeat_discovery(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        snapshots = []
        results = []
        discovery = self._discovery()
        for round_index in range(3):
            if cancel_event.is_set():
                return self._result(
                    case,
                    "skipped",
                    f"Cancelled before round {round_index + 1}",
                    evidence={"rounds": snapshots},
                )
            result = discovery.discover(
                DiscoveryConfig(
                    timeout_s=self.config.timeout_s,
                    response_delay_factor=self.config.response_delay_factor,
                    vlan_id=self.config.vlan_id,
                    min_request_interval_s=self.config.min_request_interval_s,
                ),
                cancel_event=cancel_event,
            )
            results.append(result)
            snapshots.append(
                {
                    "round": round_index + 1,
                    "xid": result.xid,
                    "devices": [
                        {
                            "mac": d.mac,
                            "name": d.name_of_station,
                            "ip": d.ip_address,
                            "rtt_ms": d.response_time_ms,
                        }
                        for d in result.devices
                    ],
                    "warnings": result.warnings,
                }
            )
        sets = [frozenset(d.mac for d in r.devices) for r in results]
        if not any(sets):
            return self._result(
                case,
                "inconclusive",
                "No devices responded in any round",
                evidence={"rounds": snapshots},
            )
        if len(set(sets)) == 1:
            return self._result(
                case,
                "passed",
                f"Device set stable across 3 paced discoveries ({len(sets[0])} device(s))",
                evidence={"rounds": snapshots},
            )
        return self._result(
            case,
            "inconclusive",
            "Device set changed between rounds; check link stability and multicast filtering",
            evidence={"rounds": snapshots},
        )

    def _test_protocol_response_times(self, case, cancel_event) -> TestResult:
        result = self.latest_discovery
        if result is None or not result.devices:
            return self._result(
                case,
                "skipped",
                "Run 'Multicast Identify discovery' first; no response-time samples are available.",
            )
        times = [d.response_time_ms for d in result.devices if d.response_time_ms is not None]
        if not times:
            return self._result(case, "skipped", "Responses did not contain timing samples")
        evidence = {
            "samples": len(times),
            "min_ms": min(times),
            "max_ms": max(times),
            "mean_ms": round(sum(times) / len(times), 3),
        }
        return self._result(
            case,
            "passed",
            f"{len(times)} response time sample(s): min {min(times):.3f} ms, "
            f"max {max(times):.3f} ms (measurement only, no SLA)",
            evidence=evidence,
        )

    def _test_validation_station_name(self, case, cancel_event) -> TestResult:
        valid = ["line-01.conveyor", "a", "", "port-1.device"]
        invalid = ["Line-01", "-device", "device-", "a..b", "192.168.1.10", "port-001"]
        failures = []
        for name in valid:
            report = validate_station_name(name)
            if not report.ok:
                failures.append(f"valid name rejected: {name!r} ({report.summary()})")
        for name in invalid:
            report = validate_station_name(name)
            if report.ok:
                failures.append(f"invalid name accepted: {name!r}")
        if failures:
            return self._result(case, "failed", "; ".join(failures))
        return self._result(
            case,
            "passed",
            "Station-name validation matches the documented PROFINET rules",
            evidence={"valid": valid, "invalid": invalid},
        )

    def _test_validation_ip_suite(self, case, cancel_event) -> TestResult:
        checks = {
            "valid": validate_ip_suite("192.168.1.10", "255.255.255.0", "192.168.1.1").ok,
            "gateway_off_subnet": not validate_ip_suite(
                "192.168.1.10", "255.255.255.0", "10.0.0.1"
            ).ok,
            "broadcast": not validate_ip_suite(
                "192.168.1.255", "255.255.255.0", "192.168.1.1"
            ).ok,
            "loopback": not validate_ip_suite("127.0.0.1", "255.0.0.0", "0.0.0.0").ok,
            "non_contiguous_mask": not validate_ip_suite(
                "192.168.1.10", "255.0.255.0", "192.168.1.1"
            ).ok,
        }
        if all(checks.values()):
            return self._result(
                case, "passed", "IPv4 suite validation behaves as documented", evidence=checks
            )
        return self._result(
            case,
            "failed",
            "IPv4 validation mismatch: " + ", ".join(k for k, v in checks.items() if not v),
            evidence=checks,
        )

    # -------------------------------------------------- guarded state changes
    def _write_config(self) -> WriteConfig:
        timeout_s = max(0.5, float(self.config.timeout_s))
        return WriteConfig(
            timeout_s=timeout_s,
            revalidate_timeout_s=timeout_s,
            verify_timeout_s=timeout_s,
            vlan_id=self.config.vlan_id,
            min_request_interval_s=self.config.min_request_interval_s,
            verify_after_set=True,
        )

    def _prepare_guarded_write(
        self,
        case: TestCase,
        *,
        kind: str,
        params: dict,
        spec: OperationSpec,
    ) -> tuple[WriteRequest | None, str]:
        if self.target is None:
            return None, "No target device was passed to the test runner."
        if not self.safety_gate.configuration_mode:
            return None, "Configuration mode is OFF; this test is skipped."
        authorization = self.write_authorizations.get(case.test_id)
        if authorization is None:
            return None, "No per-operation confirmation was supplied for this test."
        confirmation = confirmation_for(
            spec,
            interface_id=self.transport.interface.id,
            interface_name=self.transport.interface.display_name,
            target_mac=self.target.mac,
            target_identity=identity_text(self.target),
            operation_id=case.test_id,
        )
        request = WriteRequest(
            kind=kind,
            target_mac=self.target.mac,
            confirmation=confirmation,
            authorization=authorization,
            config=self._write_config(),
            **params,
        )
        return request, ""

    def _write_outcome(self, case, result, *, reset: bool = False) -> TestResult:
        evidence = {"target": result.target_mac, "write": result.to_dict()}
        if result.state == "cancelled":
            if result.transmitted:
                return self._result(
                    case,
                    "inconclusive",
                    "Cancelled after the state-changing frame was transmitted; outcome unknown.",
                    evidence=evidence,
                    warnings=result.warnings,
                )
            return self._result(case, "skipped", "Cancelled by user", evidence=evidence)
        if result.state in ("blocked", "target_unverified"):
            return self._result(
                case,
                "skipped",
                result.error or "Safety checks blocked transmission.",
                evidence=evidence,
                warnings=result.warnings,
            )
        if result.state == "acknowledged":
            if reset:
                warnings = list(result.warnings)
                if result.post_check_detail:
                    warnings.append(result.post_check_detail)
                return self._result(
                    case,
                    "inconclusive",
                    "Reset was acknowledged, but acknowledgement is not proof of completion. "
                    "The post-check proves reachability only; erased scope is vendor-dependent.",
                    evidence=evidence,
                    warnings=warnings,
                )
            if result.verification == "verified":
                return self._result(
                    case,
                    "passed",
                    f"{result.operation_text} acknowledged and independently read back",
                    evidence=evidence,
                    warnings=result.warnings,
                )
            if result.verification == "mismatch":
                return self._result(
                    case,
                    "failed",
                    f"{result.operation_text} was acknowledged, but read-back did not match.",
                    evidence=evidence,
                    warnings=result.warnings,
                )
            return self._result(
                case,
                "inconclusive",
                f"{result.operation_text} was acknowledged, but independent verification "
                "was inconclusive.",
                evidence=evidence,
                warnings=result.warnings,
            )
        return self._result(
            case,
            "inconclusive",
            f"{result.operation_text}: {result.outcome_text}",
            evidence=evidence,
            warnings=result.warnings,
        )

    def _test_write_set_name(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        params = self.write_parameters.get(case.test_id, {})
        name = params.get("name")
        if name is None:
            return self._result(
                case, "skipped", "No NameOfStation test value was supplied by the GUI."
            )
        permanent = bool(params.get("permanent", False))
        request, reason = self._prepare_guarded_write(
            case,
            kind="set_name",
            params={"name": name, "permanent": permanent},
            spec=set_name_spec(
                name,
                permanent=permanent,
                previous_name=self.target.name_of_station if self.target else None,
            ),
        )
        if request is None:
            return self._result(case, "skipped", reason)
        result = self._writer().execute(request, cancel_event=cancel_event)
        return self._write_outcome(case, result)

    def _test_write_set_ip(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        params = self.write_parameters.get(case.test_id, {})
        ip = params.get("ip_address")
        mask = params.get("subnet_mask")
        if not ip or not mask:
            return self._result(
                case, "skipped", "No IPv4 test values were supplied by the GUI."
            )
        gateway = params.get("gateway", "")
        permanent = bool(params.get("permanent", False))
        request, reason = self._prepare_guarded_write(
            case,
            kind="set_ip",
            params={
                "ip_address": ip,
                "subnet_mask": mask,
                "gateway": gateway,
                "permanent": permanent,
            },
            spec=set_ip_spec(
                ip,
                mask,
                gateway,
                permanent=permanent,
                previous_ip=self.target.ip_text if self.target else None,
            ),
        )
        if request is None:
            return self._result(case, "skipped", reason)
        result = self._writer().execute(request, cancel_event=cancel_event)
        return self._write_outcome(case, result)

    def _test_write_reset(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        params = self.write_parameters.get(case.test_id, {})
        mode = int(params.get("reset_mode", 8))
        if mode not in (1, 2, 4, 8):
            return self._result(
                case, "skipped", f"Reset mode {mode} is not implemented by this build."
            )
        request, reason = self._prepare_guarded_write(
            case,
            kind="reset",
            params={"reset_mode": mode},
            spec=reset_mode_spec(mode),
        )
        if request is None:
            return self._result(case, "skipped", reason)
        writer = self._writer()
        result = writer.execute(request, cancel_event=cancel_event)
        if result.state == "acknowledged" and not cancel_event.is_set():
            writer.post_check(
                result,
                timeout_s=max(0.5, min(float(self.config.timeout_s), 3.0)),
                cancel_event=cancel_event,
            )
        return self._write_outcome(case, result, reset=True)

