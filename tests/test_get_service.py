from __future__ import annotations

import threading

from dcpstudio.codec import parse_frame
from dcpstudio.mock import MockDeviceConfig, MockNetwork, MockTransport, default_mock_devices
from dcpstudio.services.get import GET_PRESETS, GetConfig, GetService
from dcpstudio.services.rate_limit import RequestRateLimiter

DEVICE = default_mock_devices()[0]
OTHER = default_mock_devices()[1]


def _service() -> tuple[MockTransport, GetService]:
    transport = MockTransport(MockNetwork())
    transport.start_capture()
    service = GetService(transport)
    transport.set_frame_callback(
        lambda raw, ts, direction: service.process_frame(raw, ts, direction)
    )
    return transport, service


def test_get_identity_blocks_succeed():
    transport, service = _service()
    try:
        result = service.get(
            DEVICE.mac,
            GetConfig(timeout_s=0.5, selectors=GET_PRESETS["identity"].selectors),
        )
    finally:
        transport.close()
    assert result.state == "response_received"
    assert len(result.blocks) == 6
    assert result.block_errors == []
    assert result.identity is not None
    assert result.identity.source == "get"
    assert result.identity.name_of_station == "line-01.conveyor"
    assert result.identity.ip_address == "192.0.2.11"
    assert result.identity.vendor_id == 0x002A
    assert result.rtt_ms is not None
    assert [t.outcome for t in result.transactions] == [
        "transmitted",
        "matching_response_received",
    ]
    request = parse_frame(bytes.fromhex(result.request_frame_hex))
    assert request.service_id == 0x03
    assert request.service_type == 0x00
    assert len(request.blocks) == 6


def test_get_timeout_is_outcome_unknown():
    transport = MockTransport(MockNetwork(devices=[]))
    transport.start_capture()
    service = GetService(transport)
    sent: list[bytes] = []
    transport.set_frame_callback(
        lambda raw, ts, direction: sent.append(raw) if direction == "tx" else None
    )
    try:
        result = service.get(DEVICE.mac, GetConfig(timeout_s=0.5))
    finally:
        transport.close()
    assert result.state == "no_response"
    assert len(sent) == 1
    assert result.warnings
    assert any(t.outcome == "outcome_unknown" for t in result.transactions)


def test_get_wrong_xid_is_unrelated():
    transport = MockTransport(MockNetwork(devices=[]))
    transport.start_capture()
    service = GetService(transport)
    responder = MockNetwork([DEVICE])

    def listener(raw: bytes, ts, direction: str) -> None:
        if direction == "tx":
            correct = responder.build_get_response(DEVICE, parse_frame(raw))
            wrong = correct[:18] + b"\xde\xad\xbe\xef" + correct[22:]
            transport.feed(wrong)
        else:
            service.process_frame(raw, ts, direction)

    transport.set_frame_callback(listener)
    try:
        result = service.get(
            DEVICE.mac,
            GetConfig(timeout_s=0.5, selectors=GET_PRESETS["name"].selectors),
        )
    finally:
        transport.close()
    assert result.state == "no_response"
    assert any(t.outcome == "unrelated_response_ignored" for t in result.transactions)
    assert any("unrelated" in warning for warning in result.warnings)


def test_get_response_from_wrong_target_is_unrelated():
    transport = MockTransport(MockNetwork(devices=[]))
    transport.start_capture()
    service = GetService(transport)
    responder = MockNetwork([OTHER])

    def listener(raw: bytes, ts, direction: str) -> None:
        if direction == "tx":
            response = responder.build_get_response(OTHER, parse_frame(raw))
            transport.feed(response)
        else:
            service.process_frame(raw, ts, direction)

    transport.set_frame_callback(listener)
    try:
        result = service.get(
            DEVICE.mac,
            GetConfig(timeout_s=0.5, selectors=GET_PRESETS["name"].selectors),
        )
    finally:
        transport.close()
    assert result.state == "no_response"
    assert any(t.outcome == "unrelated_response_ignored" for t in result.transactions)


def test_get_service_not_supported_response():
    transport = MockTransport(MockNetwork(devices=[]))
    transport.start_capture()
    service = GetService(transport)

    def listener(raw: bytes, ts, direction: str) -> None:
        if direction == "tx":
            frame = parse_frame(raw)
            # Same Xid/target, ServiceType 0x05, no blocks.
            response = (
                bytes.fromhex(frame.src_mac.replace(":", ""))
                + bytes.fromhex(DEVICE.mac.replace(":", ""))
                + b"\x88\x92"
                + b"\xfe\xfd"
                + bytes([0x03, 0x05])
                + frame.xid.to_bytes(4, "big")
                + b"\x00\x00\x00\x00"
            )
            transport.feed(response)
        else:
            service.process_frame(raw, ts, direction)

    transport.set_frame_callback(listener)
    try:
        result = service.get(
            DEVICE.mac,
            GetConfig(timeout_s=0.5, selectors=GET_PRESETS["name"].selectors),
        )
    finally:
        transport.close()
    assert result.state == "service_not_supported"
    assert any("0x05" in warning for warning in result.warnings)


def test_get_block_error_for_optional_alias():
    transport, service = _service()
    device = MockDeviceConfig(
        mac=DEVICE.mac,
        name=DEVICE.name,
        ip=DEVICE.ip,
        mask=DEVICE.mask,
        gateway=DEVICE.gateway,
        vendor_id=DEVICE.vendor_id,
        device_id=DEVICE.device_id,
    )
    transport.network.devices = [device]
    try:
        result = service.get(
            device.mac,
            GetConfig(
                timeout_s=0.5,
                selectors=((0x02, 0x06),),  # alias, not supported by this mock device
            ),
        )
    finally:
        transport.close()
    assert result.state == "response_received"
    assert len(result.block_errors) == 1
    assert result.block_errors[0].block_error == 0x02
    assert any("rejected" in warning for warning in result.warnings)


def test_get_late_response_is_marked():
    transport = MockTransport(MockNetwork(devices=[]))
    transport.start_capture()
    service = GetService(transport)
    responder = MockNetwork([DEVICE])

    def listener(raw: bytes, ts, direction: str) -> None:
        if direction == "tx":
            response = responder.build_get_response(DEVICE, parse_frame(raw))
            transport.feed(response, delay_s=0.6)
        else:
            service.process_frame(raw, ts, direction)

    transport.set_frame_callback(listener)
    try:
        result = service.get(
            DEVICE.mac,
            GetConfig(timeout_s=0.5, selectors=GET_PRESETS["name"].selectors),
        )
    finally:
        transport.close()
    assert result.state == "late_response"
    assert result.late is True
    assert any("after the configured timeout" in warning for warning in result.warnings)


def test_get_duplicate_response_is_ignored():
    transport = MockTransport(MockNetwork(devices=[]))
    transport.start_capture()
    service = GetService(transport)
    responder = MockNetwork([DEVICE])

    def listener(raw: bytes, ts, direction: str) -> None:
        if direction == "tx":
            response = responder.build_get_response(DEVICE, parse_frame(raw))
            transport.feed(response)
            transport.feed(response)
        else:
            service.process_frame(raw, ts, direction)

    transport.set_frame_callback(listener)
    try:
        result = service.get(
            DEVICE.mac,
            GetConfig(timeout_s=0.5, selectors=GET_PRESETS["name"].selectors),
        )
    finally:
        transport.close()
    assert result.state == "response_received"
    assert any(t.outcome == "duplicate_response_ignored" for t in result.transactions)
    assert any("duplicate" in warning for warning in result.warnings)


def test_get_cancel_before_transmission():
    transport = MockTransport(MockNetwork())
    transport.start_capture()
    limiter = RequestRateLimiter(5.0)
    limiter.note_sent()
    service = GetService(transport, limiter=limiter)
    cancel = threading.Event()
    timer = threading.Timer(0.08, cancel.set)
    timer.start()
    sent: list[bytes] = []
    transport.set_frame_callback(
        lambda raw, ts, direction: sent.append(raw) if direction == "tx" else None
    )
    try:
        result = service.get(DEVICE.mac, GetConfig(timeout_s=0.5), cancel_event=cancel)
    finally:
        transport.close()
        timer.cancel()
    assert result.state == "cancelled"
    assert result.request_frame_hex == ""
    assert sent == []
