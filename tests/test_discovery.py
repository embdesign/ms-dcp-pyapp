from __future__ import annotations

import threading
import time

import pytest

from dcpstudio.codec import IdentifyFilter, parse_frame
from dcpstudio.mock import MockDeviceConfig, MockNetwork, MockTransport
from dcpstudio.services.discovery import DiscoveryConfig, DiscoveryService
from dcpstudio.services.rate_limit import RequestRateLimiter
from dcpstudio.transport.base import TransportError

DEVICE = MockDeviceConfig(
    mac="02:00:00:00:00:21",
    name="test.device",
    ip="192.0.2.21",
    mask="255.255.255.0",
    gateway="192.0.2.1",
)


def _wired_transport(delayed: bool = False) -> tuple[MockTransport, DiscoveryService, list[bytes]]:
    transport = MockTransport(
        MockNetwork(devices=[]), response_delay_s=0.6 if delayed else 0.0
    )
    transport.start_capture()
    service = DiscoveryService(transport)
    responses: list[bytes] = []
    responder = MockNetwork([DEVICE])

    def listener(raw: bytes, ts, direction: str) -> None:
        if direction == "tx":
            request = parse_frame(raw)
            response = responder.build_identify_response(DEVICE, request)
            responses.append(response)
            transport.feed(response, delay_s=0.6 if delayed else 0.0)
        else:
            service.process_frame(raw, ts, direction)

    transport.set_frame_callback(listener)
    return transport, service, responses


def test_mock_discovery_and_transactions():
    transport = MockTransport(MockNetwork())
    transport.start_capture()
    service = DiscoveryService(transport)
    transport.set_frame_callback(
        lambda raw, ts, direction: service.process_frame(raw, ts, direction)
    )
    try:
        result = service.discover(DiscoveryConfig(timeout_s=0.5))
    finally:
        transport.close()
    assert result.outcome == "responses_received"
    assert len(result.devices) == 3
    assert result.request_count == 1
    assert result.request_frame_hex
    outcomes = [t.outcome for t in result.transactions]
    assert "transmitted" in outcomes
    assert outcomes.count("matching_response_received") == 3
    assert result.duplicate_responses == 0


def test_identify_filter_matches_alias_role_and_mac():
    first = MockDeviceConfig(
        mac="02:00:00:00:00:31",
        name="a",
        alias="port-001.a",
        vendor_id=0x002A,
        device_id=0x0101,
        role_flags=0x01,
    )
    second = MockDeviceConfig(
        mac="02:00:00:00:00:32",
        name="b",
        alias="port-002.b",
        vendor_id=0x002A,
        device_id=0x0202,
        role_flags=0x02,
    )
    transport = MockTransport(MockNetwork([first, second]))
    transport.start_capture()
    service = DiscoveryService(transport, limiter=RequestRateLimiter(0.01))
    transport.set_frame_callback(
        lambda raw, ts, direction: service.process_frame(raw, ts, direction)
    )
    try:
        by_alias = service.discover(
            DiscoveryConfig(
                timeout_s=0.5, identify_filter=IdentifyFilter(alias="port-002.b")
            )
        )
        by_role = service.discover(
            DiscoveryConfig(
                timeout_s=0.5, identify_filter=IdentifyFilter(device_role=0x01)
            )
        )
        by_mac = service.discover(
            DiscoveryConfig(
                timeout_s=0.5,
                identify_filter=IdentifyFilter(mac="02:00:00:00:00:32"),
            )
        )
        by_vendor = service.discover(
            DiscoveryConfig(
                timeout_s=0.5,
                identify_filter=IdentifyFilter(vendor_name="Mock Automation"),
            )
        )
    finally:
        transport.close()
    assert [d.mac for d in by_alias.devices] == ["02:00:00:00:00:32"]
    assert [d.mac for d in by_role.devices] == ["02:00:00:00:00:31"]
    assert [d.mac for d in by_mac.devices] == ["02:00:00:00:00:32"]
    assert [d.mac for d in by_vendor.devices] == [
        "02:00:00:00:00:31",
        "02:00:00:00:00:32",
    ]
    assert by_alias.identify_filter_text == "alias 'port-002.b'"


def test_duplicate_response_is_merged():
    transport = MockTransport(MockNetwork(devices=[]))
    transport.start_capture()
    service = DiscoveryService(transport)
    responder = MockNetwork([DEVICE])

    def listener(raw: bytes, ts, direction: str) -> None:
        if direction == "tx":
            request = parse_frame(raw)
            response = responder.build_identify_response(DEVICE, request)
            transport.feed(response)
            transport.feed(response)
        else:
            service.process_frame(raw, ts, direction)

    transport.set_frame_callback(listener)
    result = service.discover(DiscoveryConfig(timeout_s=0.5))
    transport.close()
    assert len(result.devices) == 1
    assert result.duplicate_responses == 1
    assert result.devices[0].response_count == 2


def test_wrong_xid_is_unrelated():
    transport, service, responses = _wired_transport()

    def listener(raw: bytes, ts, direction: str) -> None:
        if direction == "tx":
            # Build a response then corrupt the Xid at DCP header offset 18..21.
            responder = MockNetwork([DEVICE])
            correct = responder.build_identify_response(DEVICE, parse_frame(raw))
            wrong = correct[:18] + b"\xde\xad\xbe\xef" + correct[22:]
            transport.feed(wrong)
            transport.feed(correct)
        else:
            service.process_frame(raw, ts, direction)

    transport.set_frame_callback(listener)
    result = service.discover(DiscoveryConfig(timeout_s=0.5))
    transport.close()
    assert len(result.devices) == 1
    assert result.unmatched_responses == 1
    assert any(t.outcome == "unrelated_response_ignored" for t in result.transactions)


def test_timeout_reports_outcome_unknown_without_retry():
    transport = MockTransport(MockNetwork(devices=[]))
    transport.start_capture()
    service = DiscoveryService(transport)
    sent: list[bytes] = []
    transport.set_frame_callback(
        lambda raw, ts, direction: sent.append(raw) if direction == "tx" else None
    )
    result = service.discover(DiscoveryConfig(timeout_s=0.5))
    transport.close()
    assert result.outcome == "no_responses"
    assert len(sent) == 1  # no automatic retry
    assert any(t.outcome == "outcome_unknown" for t in result.transactions)
    assert any("does not prove" in warning for warning in result.warnings)


def test_late_response_is_marked(monkeypatch):
    # Widen the late-response observation window for this test only: the
    # production default (0.15 s) is smaller than scheduler jitter on a loaded
    # machine, which made this test flaky before the refactor as well.
    monkeypatch.setattr(
        "dcpstudio.services.discovery.LATE_RESPONSE_GRACE_S", 5.0
    )
    transport, service, _responses = _wired_transport(delayed=True)
    result = service.discover(DiscoveryConfig(timeout_s=0.5))
    transport.close()
    assert result.late_responses == 1
    assert len(result.devices) == 1
    assert any("after the configured timeout" in w for w in result.devices[0].warnings)
    assert any(t.outcome == "late_response" for t in result.transactions)


def test_rate_limiter_waits_and_cancels():
    limiter = RequestRateLimiter(0.2)
    limiter.note_sent()
    start = time.monotonic()
    assert limiter.wait() is True
    assert time.monotonic() - start >= 0.15

    # Cancellation is checked deterministically: an already-set event must make
    # the limiter return immediately. (The timer-based variant of this test was
    # flaky on loaded machines.)
    cancel = threading.Event()
    cancel.set()
    limiter.note_sent()
    assert limiter.wait(cancel) is False


def test_cancel_before_transmission_sends_nothing():
    transport = MockTransport(MockNetwork())
    transport.start_capture()
    limiter = RequestRateLimiter(5.0)
    limiter.note_sent()
    service = DiscoveryService(transport, limiter=limiter)
    cancel = threading.Event()
    timer = threading.Timer(0.08, cancel.set)
    timer.start()
    sent: list[bytes] = []
    transport.set_frame_callback(
        lambda raw, ts, direction: sent.append(raw) if direction == "tx" else None
    )
    result = service.discover(DiscoveryConfig(timeout_s=0.5), cancel_event=cancel)
    transport.close()
    timer.cancel()
    assert result.cancelled is True
    assert result.request_frame_hex == ""
    assert sent == []


def test_name_filtered_discovery_returns_only_the_matching_device():
    transport = MockTransport(MockNetwork())
    transport.start_capture()
    service = DiscoveryService(transport)
    transport.set_frame_callback(
        lambda raw, ts, direction: service.process_frame(raw, ts, direction)
    )
    try:
        result = service.discover(
            DiscoveryConfig(timeout_s=0.5, identify_filter_name="line-01.robot")
        )
    finally:
        transport.close()
    assert result.outcome == "responses_received"
    assert [device.name_of_station for device in result.devices] == ["line-01.robot"]
    assert result.identify_filter_name == "line-01.robot"


def test_name_filtered_discovery_no_match_is_outcome_unknown():
    transport = MockTransport(MockNetwork())
    transport.start_capture()
    service = DiscoveryService(transport)
    transport.set_frame_callback(
        lambda raw, ts, direction: service.process_frame(raw, ts, direction)
    )
    try:
        result = service.discover(
            DiscoveryConfig(timeout_s=0.5, identify_filter_name="does-not-exist")
        )
    finally:
        transport.close()
    assert result.outcome == "no_responses"
    assert result.devices == []
    assert any("NameOfStation filter" in warning for warning in result.warnings)


def test_invalid_name_filter_is_rejected_before_transmission():
    transport = MockTransport(MockNetwork())
    transport.start_capture()
    service = DiscoveryService(transport)
    sent: list[bytes] = []
    transport.set_frame_callback(
        lambda raw, ts, direction: sent.append(raw) if direction == "tx" else None
    )
    try:
        with pytest.raises(TransportError):
            service.discover(
                DiscoveryConfig(timeout_s=0.5, identify_filter_name="Bad.Name")
            )
    finally:
        transport.close()
    assert sent == []
