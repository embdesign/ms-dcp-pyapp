"""Handlers for the ``protocol.*`` functional-test namespace."""

from __future__ import annotations

from ...codec import build_get_request, parse_frame
from ...constants import Option, ServiceId, ServiceType
from ...mock import MockNetwork, MockTransport, default_mock_devices
from ...model import TestResult
from ...services.discovery import DiscoveryConfig, DiscoveryService
from ...services.get import GET_PRESETS, GetConfig


class ProtocolHandlersMixin:
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
                case,
                "failed",
                "Matching response was not attributed to a device",
                evidence=evidence,
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

    def _test_protocol_identity_completeness(self, case, cancel_event) -> TestResult:
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
            self.latest_discovery = discovery.discover(
                base_config, cancel_event=cancel_event
            )
        if self.latest_discovery.cancelled:
            return self._result(case, "skipped", "Cancelled during discovery")
        devices = [
            device
            for device in self.latest_discovery.devices
            if not any("after the configured timeout" in w for w in device.warnings)
        ]
        if not devices:
            return self._result(
                case,
                "inconclusive",
                "No device responded to Identify; there is nothing to validate.",
                evidence={"discovery": self.latest_discovery.to_dict()},
            )
        findings = []
        missing: list[str] = []
        warnings: list[str] = []
        for device in devices:
            absent: list[str] = []
            if device.vendor_id is None or device.device_id is None:
                absent.append("DeviceProperties (vendor/device ID)")
            if not device.device_options:
                absent.append("supported options")
            if absent:
                missing.append(f"{device.mac}: {', '.join(absent)}")
            if not device.name_of_station:
                warnings.append(f"{device.mac}: no NameOfStation advertised")
            if not device.ip_address or device.ip_address == "0.0.0.0":
                warnings.append(f"{device.mac}: no IPv4 parameter advertised")
            findings.append(
                {
                    "mac": device.mac,
                    "vendor_device": device.vendor_device_text,
                    "name": device.name_of_station,
                    "ip": device.ip_address,
                    "options": device.options_text,
                    "missing": absent,
                }
            )
        evidence = {"devices": findings}
        if missing:
            return self._result(
                case,
                "inconclusive",
                f"Identity is incomplete for {len(missing)} device(s): "
                + "; ".join(missing)
                + ". Reported as an observation, not as a defect.",
                evidence=evidence,
                warnings=warnings,
            )
        return self._result(
            case,
            "passed",
            f"{len(devices)} device(s) advertise DeviceProperties and their supported "
            "options"
            + (f"; {len(warnings)} name/IP observation(s)" if warnings else ""),
            evidence=evidence,
            warnings=warnings,
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
        target = self.target
        if target is None:
            if self.latest_discovery is None or not self.latest_discovery.devices:
                self.latest_discovery = discovery.discover(
                    base_config, cancel_event=cancel_event
                )
            if self.latest_discovery.cancelled:
                return self._result(case, "skipped", "Cancelled by user")
            if not self.latest_discovery.devices:
                return self._result(
                    case,
                    "inconclusive",
                    "No device is available for a unicast Identify; run multicast "
                    "discovery first or select a device.",
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
        target = self.target
        if target is None:
            if self.latest_discovery is None or not self.latest_discovery.devices:
                self.latest_discovery = discovery.discover(
                    base_config, cancel_event=cancel_event
                )
            if self.latest_discovery.cancelled:
                return self._result(case, "skipped", "Cancelled during discovery")
            if not self.latest_discovery.devices:
                return self._result(
                    case,
                    "inconclusive",
                    "No device is available for a live Get; discovery observed no "
                    "response and no device is selected.",
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
            "target": result.identity is not None
            and result.identity.mac.lower() == target.mac.lower(),
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
