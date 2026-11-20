"""DCP Signal (05/03) service tests.

Signal is an identification aid: it needs no confirmation, sends exactly one
unicast frame, and is never retried.
"""

from __future__ import annotations

from dcpstudio.mock import MockNetwork, MockTransport, default_mock_devices
from dcpstudio.services.rate_limit import RequestRateLimiter
from dcpstudio.services.signal import SignalService


def _service(*, delay_s: float = 0.0) -> tuple[MockTransport, SignalService, str]:
    device = default_mock_devices()[0]
    transport = MockTransport(MockNetwork([device]), response_delay_s=delay_s)
    service = SignalService(transport, limiter=RequestRateLimiter(0.01))
    transport.set_frame_callback(
        lambda raw, ts, direction: service.process_frame(raw, ts, direction)
    )
    transport.start_capture()
    return transport, service, device.mac


def test_signal_is_acknowledged_without_confirmation():
    transport, service, mac = _service()
    try:
        result = service.signal(mac, timeout_s=0.5)
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert result.response_verdict == "acknowledged"
    assert result.block_error == 0x00
    assert result.block_qualifier == 0x0000
    assert result.operation == "signal"
    assert result.request_frame_hex.endswith("0503000400000100")
    assert result.verification == "not_attempted"
    assert "LED" in result.verification_detail
    events = [t.event for t in result.transactions]
    assert events.count("signal_request") == 1
    assert events.count("signal_response") == 1


def test_signal_needs_passive_capture():
    transport, service, mac = _service()
    transport.close()  # capture stopped
    result = service.signal(mac, timeout_s=0.5)
    assert result.state == "blocked"
    assert "capture" in (result.error or "").lower()
    assert result.request_frame_hex


def test_signal_timeout_is_outcome_unknown():
    transport, service, mac = _service(delay_s=2.0)
    try:
        result = service.signal(mac, timeout_s=0.3)
    finally:
        transport.close()
    assert result.state == "no_response"
    assert any("outcome unknown" in w for w in result.warnings)
    assert [t.event for t in result.transactions].count("signal_request") == 1


def test_signal_refuses_multicast_and_broadcast():
    transport, service, _ = _service()
    try:
        for target in ("01:0e:cf:00:00:00", "ff:ff:ff:ff:ff:ff"):
            result = service.signal(target, timeout_s=0.3)
            assert result.state == "blocked"
            assert result.request_frame_hex == ""
    finally:
        transport.close()


def test_signal_calls_event_log_with_three_arguments():
    """The EventLog contract is (event, message, detail) — no level argument.

    The GUI passes ``MainWindow._service_log`` as ``event_log``; a fourth
    argument raised ``TypeError`` only when a Signal was actually sent.
    """
    device = default_mock_devices()[0]
    transport = MockTransport(MockNetwork([device]))
    calls: list[tuple[str, str, dict]] = []

    def event_log(event: str, message: str, detail: dict) -> None:
        calls.append((event, message, detail))

    service = SignalService(
        transport, limiter=RequestRateLimiter(0.01), event_log=event_log
    )
    transport.set_frame_callback(
        lambda raw, ts, direction: service.process_frame(raw, ts, direction)
    )
    transport.start_capture()
    try:
        result = service.signal(device.mac, timeout_s=0.5)
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert [call[0] for call in calls] == ["signal.request_transmitted"]
    assert calls[0][2]["target"] == device.mac


def test_unrelated_frames_do_not_break_correlation():
    from dcpstudio.model import utc_now

    transport, service, mac = _service()
    try:
        service.process_frame(b"", utc_now(), "rx")            # empty frame
        service.process_frame(b"\x00" * 24, utc_now(), "rx")   # garbage
        service.process_frame(b"\x00" * 24, utc_now(), "tx")   # own transmission
        result = service.signal(mac, timeout_s=0.5)
    finally:
        transport.close()
    assert result.state == "acknowledged"
