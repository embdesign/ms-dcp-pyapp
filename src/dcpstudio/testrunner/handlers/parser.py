"""Handlers for the ``parser.*`` functional-test namespace."""

from __future__ import annotations

import struct

from ...codec import (
    classify_set_response,
    encode_block,
    extract_device_identity,
    parse_frame,
)
from ...constants import (
    ETHERTYPE_PROFINET,
    ControlSubOption,
    FrameId,
    Option,
    ServiceId,
    ServiceType,
)
from ...fixtures import get_fixture
from ...model import TestResult, utc_now
from ...pcap_io import analyze_pcap, write_pcap


class ParserHandlersMixin:
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
            return self._result(
                case, "passed", "All fixture fields decoded correctly", evidence=evidence
            )
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

        from ...model import CapturedFrame

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
