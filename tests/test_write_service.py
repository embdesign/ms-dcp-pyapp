from __future__ import annotations

import threading

import pytest

from dcpstudio.codec import parse_frame
from dcpstudio.constants import DCP_MULTICAST_MAC, ServiceId
from dcpstudio.mock import MockNetwork, MockTransport, default_mock_devices
from dcpstudio.safety import ConfirmationRequest, SafetyGate
from dcpstudio.services.discovery import DiscoveryConfig, DiscoveryService
from dcpstudio.services.get import GetService
from dcpstudio.services.rate_limit import RequestRateLimiter
from dcpstudio.services.write import (
    WriteAuthorization,
    WriteConfig,
    WriteRequest,
    WriteService,
    identity_text,
)

DEVICE = default_mock_devices()[0]


def _config() -> WriteConfig:
    return WriteConfig(
        timeout_s=0.5,
        revalidate_timeout_s=0.5,
        verify_timeout_s=0.5,
        min_request_interval_s=0.02,
    )


def _auth() -> WriteAuthorization:
    return WriteAuthorization(
        authorization_confirmed=True,
        safe_maintenance_confirmed=True,
    )


def _setup(*, apply_set: bool = True, delay_s: float = 0.0):
    device = default_mock_devices()[0]
    transport = MockTransport(
        MockNetwork([device], apply_set=apply_set), response_delay_s=delay_s
    )
    transport.start_capture()
    limiter = RequestRateLimiter(0.02)
    discovery = DiscoveryService(transport, limiter=limiter)
    getter = GetService(transport, limiter=limiter)
    gate = SafetyGate()
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
    )
    transport.set_frame_callback(
        lambda raw, ts, direction: (
            discovery.process_frame(raw, ts, direction),
            getter.process_frame(raw, ts, direction),
            writer.process_frame(raw, ts, direction),
        )
    )
    target = discovery.discover(
        DiscoveryConfig(timeout_s=max(0.5, delay_s + 0.5))
    ).devices[0]
    return device, transport, discovery, getter, writer, gate, target


def _confirmation(target, kind: str = "set_name"):
    factory = kind == "reset"
    return ConfirmationRequest(
        operation_id=kind,
        operation_text="ResetToFactorySettings" if factory else "Set",
        interface_id=target.interface_id,
        target_mac=target.mac,
        target_identity=identity_text(target),
        proposed_parameters={"test": True},
        destructiveness="factory-reset" if factory else "state-changing",
    )


def _setup_with_network(network: MockNetwork):
    transport = MockTransport(network)
    transport.start_capture()
    limiter = RequestRateLimiter(0.02)
    discovery = DiscoveryService(transport, limiter=limiter)
    getter = GetService(transport, limiter=limiter)
    gate = SafetyGate()
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
    )
    transport.set_frame_callback(
        lambda raw, ts, direction: (
            discovery.process_frame(raw, ts, direction),
            getter.process_frame(raw, ts, direction),
            writer.process_frame(raw, ts, direction),
        )
    )
    target = discovery.discover(DiscoveryConfig(timeout_s=0.5)).devices[0]
    return transport, writer, target


def _is_unicast_identify(raw: bytes) -> bool:
    frame = parse_frame(raw)
    return (
        frame.service_id == int(ServiceId.IDENTIFY)
        and (frame.dst_mac or "").lower() != DCP_MULTICAST_MAC
    )


class _UnicastDeafNetwork(MockNetwork):
    """Answers multicast Identify but ignores the unicast form."""

    def handle_request(self, raw: bytes) -> list[bytes]:
        if _is_unicast_identify(raw):
            return []
        return super().handle_request(raw)


class _DropIdentifyNetwork(MockNetwork):
    """Ignores the next ``drop`` Identify requests (simulated reboot)."""

    def __init__(self, *args, drop: int = 0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.drop = drop
        self._drop_lock = threading.Lock()

    def handle_request(self, raw: bytes) -> list[bytes]:
        if parse_frame(raw).service_id == int(ServiceId.IDENTIFY):
            with self._drop_lock:
                if self.drop > 0:
                    self.drop -= 1
                    return []
        return super().handle_request(raw)


class _SilentIdentifyNetwork(MockNetwork):
    """Answers nothing to Identify, so a post-check cannot succeed."""

    def handle_request(self, raw: bytes) -> list[bytes]:
        if parse_frame(raw).service_id == int(ServiceId.IDENTIFY):
            return []
        return super().handle_request(raw)


def test_set_name_is_acknowledged_and_verified():
    device, transport, _, _, writer, _, target = _setup()
    try:
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=False,
            )
        )
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert result.response_verdict == "acknowledged"
    assert result.verification == "verified"
    assert result.block_qualifier == 0x0000
    assert device.name == "line-77.tested"
    assert [t.event for t in result.transactions].count("set_request") == 1
    assert [t.event for t in result.transactions].count("get_request") == 1


def test_set_ip_permanent_is_acknowledged_and_verified():
    device, transport, _, _, writer, _, target = _setup()
    try:
        result = writer.execute(
            WriteRequest(
                "set_ip",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                ip_address="192.0.2.77",
                subnet_mask="255.255.255.0",
                gateway="192.0.2.1",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert result.verification == "verified"
    assert result.block_qualifier == 0x0001
    assert device.ip == "192.0.2.77"


def test_unconfirmed_write_is_blocked_without_transmission():
    device, transport, _, _, writer, _, target = _setup()
    try:
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                WriteAuthorization(
                    authorization_confirmed=True,
                    safe_maintenance_confirmed=False,
                ),
                _config(),
                name="line-77.tested",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "blocked"
    assert result.request_frame_hex == ""
    assert device.name == DEVICE.name


def test_missing_authorization_blocks_write_without_transmission():
    device, transport, _, _, writer, _, target = _setup()
    try:
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                WriteAuthorization(),
                _config(),
                name="line-77.tested",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "blocked"
    assert result.request_frame_hex == ""
    assert device.name == DEVICE.name


def test_target_identity_change_blocks_write():
    device, transport, _, _, writer, _, target = _setup()
    confirmation = _confirmation(target)
    confirmation.target_identity = "stale identity"
    try:
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                confirmation,
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "target_unverified"
    assert result.request_frame_hex == ""
    assert device.name == DEVICE.name


def test_rejected_set_is_reported():
    device, transport, _, _, writer, _, target = _setup(apply_set=False)
    try:
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "rejected"
    assert result.block_error == 0x05
    assert result.verification == "not_attempted"
    assert device.name == DEVICE.name


def test_reset_is_acknowledged_and_post_check_responds():
    device, transport, _, _, writer, _, target = _setup()
    confirmation = _confirmation(target, "reset")
    try:
        result = writer.execute(
            WriteRequest(
                "reset",
                target.mac,
                confirmation,
                WriteAuthorization(
                    authorization_confirmed=True,
                    safe_maintenance_confirmed=True,
                ),
                _config(),
                reset_mode=8,
            )
        )
        assert result.state == "acknowledged"
        assert result.block_qualifier == 0x0010
        assert result.verification == "not_attempted"
        assert device.name == ""
        result = writer.post_check(result, timeout_s=0.5)
    finally:
        transport.close()
    assert result.post_check_state == "responded"
    assert result.after_identity is not None
    assert result.after_identity.name_of_station == ""


def test_legacy_factory_reset_is_guarded_and_acknowledged():
    device, transport, _, _, writer, _, target = _setup()
    confirmation = _confirmation(target, "reset")
    try:
        result = writer.execute(
            WriteRequest(
                "reset_legacy",
                target.mac,
                confirmation,
                _auth(),
                _config(),
            )
        )
        assert result.state == "acknowledged"
        assert result.block_qualifier == 0x0000
        assert result.verification == "not_attempted"
        assert "not proof of completion" in result.verification_detail
        assert result.request_frame_hex.endswith("050500020000")
        assert device.name == ""
        assert device.ip == "0.0.0.0"
        result = writer.post_check(result, timeout_s=0.5)
    finally:
        transport.close()
    assert result.post_check_state == "responded"


def test_legacy_factory_reset_refuses_a_reset_mode():
    device, transport, _, _, writer, _, target = _setup()
    try:
        result = writer.execute(
            WriteRequest(
                "reset_legacy",
                target.mac,
                _confirmation(target, "reset"),
                _auth(),
                _config(),
                reset_mode=8,
            )
        )
    finally:
        transport.close()
    assert result.state == "blocked"
    assert result.request_frame_hex == ""
    assert result.transactions == []
    assert device.name == DEVICE.name


def test_legacy_factory_reset_requires_both_confirmations():
    device, transport, _, _, writer, _, target = _setup()
    try:
        result = writer.execute(
            WriteRequest(
                "reset_legacy",
                target.mac,
                _confirmation(target, "reset"),
                WriteAuthorization(authorization_confirmed=True),
                _config(),
            )
        )
    finally:
        transport.close()
    assert result.state == "blocked"
    assert result.request_frame_hex == ""
    assert device.name == DEVICE.name


def test_invalid_name_is_blocked_before_any_network_traffic():
    device, transport, _, _, writer, _, target = _setup()
    try:
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="UPPERCASE",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "blocked"
    assert result.request_frame_hex == ""
    assert result.transactions == []
    assert device.name == DEVICE.name


def test_set_with_verification_disabled_is_not_claimed_verified():
    device, transport, _, _, writer, _, target = _setup()
    try:
        cfg = _config()
        cfg.verify_after_set = False
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                cfg,
                name="line-77.tested",
                permanent=False,
            )
        )
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert result.verification == "not_attempted"
    assert "disabled" in result.verification_detail.lower()
    assert "reset" not in result.verification_detail.lower()
    assert device.name == "line-77.tested"


def test_late_set_response_is_distinguished(monkeypatch):
    # Test-only: widen the late-response window so scheduler jitter cannot
    # decide the outcome (the production default stays 0.15 s).
    monkeypatch.setattr("dcpstudio.services.write.LATE_RESPONSE_GRACE_S", 5.0)
    device, transport, _, _, writer, _, target = _setup(delay_s=0.58)
    try:
        # Revalidation must be in-window (0.58 s < 1.0 s); only the Set response
        # is intended to be late relative to its 0.5 s timeout.
        config = _config()
        config.revalidate_timeout_s = 1.0
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                config,
                name="line-77.tested",
                permanent=False,
            )
        )
    finally:
        transport.close()
    assert result.state == "late_response"
    assert result.response_verdict == "acknowledged"
    assert result.late is True
    assert any("after the configured timeout" in w for w in result.warnings)


def test_set_readback_mismatch_is_reported():
    device = default_mock_devices()[0]
    copy_device = default_mock_devices()[0]
    responder = MockNetwork([device])
    ack_network = MockNetwork([copy_device])
    transport = MockTransport(MockNetwork([]))
    transport.start_capture()
    limiter = RequestRateLimiter(0.02)
    discovery = DiscoveryService(transport, limiter=limiter)
    getter = GetService(transport, limiter=limiter)
    gate = SafetyGate()
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
    )

    def callback(raw, ts, direction):
        discovery.process_frame(raw, ts, direction)
        getter.process_frame(raw, ts, direction)
        writer.process_frame(raw, ts, direction)
        if direction == "tx":
            frame = parse_frame(raw)
            if frame.service_id == 0x05:
                transport.feed(responder.build_identify_response(device, frame))
            elif frame.service_id == 0x04:
                transport.feed(ack_network.build_set_response(copy_device, frame))
            elif frame.service_id == 0x03:
                transport.feed(responder.build_get_response(device, frame))

    transport.set_frame_callback(callback)
    try:
        target = discovery.discover(DiscoveryConfig(timeout_s=0.5)).devices[0]
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=False,
            )
        )
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert result.verification == "mismatch"
    assert device.name == DEVICE.name


def test_set_service_not_supported_is_reported():
    device = default_mock_devices()[0]
    responder = MockNetwork([device])
    transport = MockTransport(MockNetwork([]))
    transport.start_capture()
    limiter = RequestRateLimiter(0.02)
    discovery = DiscoveryService(transport, limiter=limiter)
    getter = GetService(transport, limiter=limiter)
    gate = SafetyGate()
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
    )

    def callback(raw, ts, direction):
        discovery.process_frame(raw, ts, direction)
        getter.process_frame(raw, ts, direction)
        writer.process_frame(raw, ts, direction)
        if direction == "tx":
            frame = parse_frame(raw)
            if frame.service_id == 0x05:
                transport.feed(responder.build_identify_response(device, frame))
            elif frame.service_id == 0x04:
                # Swap MACs, set ServiceType 0x05 (not supported) and no payload.
                raw_response = bytearray(raw[:26])
                raw_response[0:6], raw_response[6:12] = raw[6:12], raw[0:6]
                raw_response[17] = 0x05
                raw_response[24:26] = b"\x00\x00"
                transport.feed(bytes(raw_response))

    transport.set_frame_callback(callback)
    try:
        target = discovery.discover(DiscoveryConfig(timeout_s=0.5)).devices[0]
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=False,
            )
        )
    finally:
        transport.close()
    assert result.state == "service_not_supported"


def test_set_timeout_is_outcome_unknown():
    device = default_mock_devices()[0]
    responder = MockNetwork([device])
    transport = MockTransport(MockNetwork([]))
    transport.start_capture()
    limiter = RequestRateLimiter(0.02)
    discovery = DiscoveryService(transport, limiter=limiter)
    getter = GetService(transport, limiter=limiter)
    gate = SafetyGate()
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
    )

    def callback(raw, ts, direction):
        discovery.process_frame(raw, ts, direction)
        getter.process_frame(raw, ts, direction)
        writer.process_frame(raw, ts, direction)
        if direction == "tx":
            frame = parse_frame(raw)
            if frame.service_id == 0x05:  # Identify: answer revalidation only
                transport.feed(responder.build_identify_response(device, frame))

    transport.set_frame_callback(callback)
    try:
        target = discovery.discover(DiscoveryConfig(timeout_s=0.5)).devices[0]
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "no_response"
    assert result.verification == "not_attempted"
    assert any("outcome unknown" in warning for warning in result.warnings)
    assert [t.event for t in result.transactions].count("set_request") == 1


def test_set_response_from_wrong_source_is_ignored():
    target_device = default_mock_devices()[0]
    other_device = default_mock_devices()[1]
    responder = MockNetwork([target_device, other_device])
    transport = MockTransport(MockNetwork([]))
    transport.start_capture()
    limiter = RequestRateLimiter(0.02)
    discovery = DiscoveryService(transport, limiter=limiter)
    getter = GetService(transport, limiter=limiter)
    gate = SafetyGate()
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
    )

    def callback(raw, ts, direction):
        discovery.process_frame(raw, ts, direction)
        getter.process_frame(raw, ts, direction)
        writer.process_frame(raw, ts, direction)
        if direction == "tx":
            frame = parse_frame(raw)
            if frame.service_id == 0x05:
                transport.feed(responder.build_identify_response(target_device, frame))
            elif frame.service_id == 0x04:
                # A response for the same Xid but from a different MAC.
                transport.feed(responder.build_set_response(other_device, frame))

    transport.set_frame_callback(callback)
    try:
        target = discovery.discover(
            DiscoveryConfig(timeout_s=0.5, unicast_mac=target_device.mac)
        ).devices[0]
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "no_response"
    assert result.unmatched_responses >= 1
    assert target_device.name == DEVICE.name


def test_reset_post_check_no_response_is_unknown():
    device = default_mock_devices()[0]
    responder = MockNetwork([device])
    transport = MockTransport(MockNetwork([]))
    transport.start_capture()
    limiter = RequestRateLimiter(0.02)
    discovery = DiscoveryService(transport, limiter=limiter)
    getter = GetService(transport, limiter=limiter)
    gate = SafetyGate()
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
    )
    state = {"identify": True}

    def callback(raw, ts, direction):
        discovery.process_frame(raw, ts, direction)
        getter.process_frame(raw, ts, direction)
        writer.process_frame(raw, ts, direction)
        if direction == "tx":
            frame = parse_frame(raw)
            if frame.service_id == 0x05 and state["identify"]:
                transport.feed(responder.build_identify_response(device, frame))
            elif frame.service_id == 0x04:
                transport.feed(responder.build_set_response(device, frame))

    transport.set_frame_callback(callback)
    try:
        target = discovery.discover(DiscoveryConfig(timeout_s=0.5)).devices[0]
        confirmation = _confirmation(target, "reset")
        result = writer.execute(
            WriteRequest(
                "reset",
                target.mac,
                confirmation,
                WriteAuthorization(
                    authorization_confirmed=True,
                    safe_maintenance_confirmed=True,
                ),
                _config(),
                reset_mode=8,
            )
        )
        state["identify"] = False
        result = writer.post_check(result, timeout_s=0.5)
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert result.post_check_state == "no_response"
    assert "outcome unknown" in result.post_check_detail


def test_cancel_after_set_transmission_reports_unknown_outcome():
    import threading

    device = default_mock_devices()[0]
    responder = MockNetwork([device])
    transport = MockTransport(MockNetwork([]))
    transport.start_capture()
    limiter = RequestRateLimiter(0.02)
    discovery = DiscoveryService(transport, limiter=limiter)
    getter = GetService(transport, limiter=limiter)
    gate = SafetyGate()
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
    )

    cancel_event = threading.Event()
    timers: list[threading.Timer] = []

    def callback(raw, ts, direction):
        discovery.process_frame(raw, ts, direction)
        getter.process_frame(raw, ts, direction)
        writer.process_frame(raw, ts, direction)
        if direction == "tx":
            frame = parse_frame(raw)
            if frame.service_id == 0x05:
                transport.feed(responder.build_identify_response(device, frame))
            elif frame.service_id == 0x04:
                timer = threading.Timer(0.05, cancel_event.set)
                timers.append(timer)
                timer.start()

    transport.set_frame_callback(callback)
    try:
        target = discovery.discover(DiscoveryConfig(timeout_s=0.5)).devices[0]
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                WriteConfig(
                    timeout_s=2.0,
                    revalidate_timeout_s=0.5,
                    verify_timeout_s=0.5,
                    min_request_interval_s=0.02,
                ),
                name="line-77.tested",
                permanent=True,
            ),
            cancel_event=cancel_event,
        )
        for timer in timers:
            timer.cancel()
    finally:
        transport.close()
    assert result.state == "cancelled"
    assert result.transmitted is True
    assert "outcome is unknown" in " ".join(result.warnings)
    assert any(t.event == "set_cancelled" for t in result.transactions)


def test_guarded_service_refuses_signal():
    """Signal is an identification aid, not a guarded write (see SignalService).

    The guarded dispatcher must not grow an unguarded branch: an unknown kind is
    rejected outright, before any frame could be built.
    """
    device, transport, _, _, writer, _, target = _setup()
    try:
        with pytest.raises(ValueError, match="Unsupported write operation"):
            writer.execute(
                WriteRequest(
                    "signal",
                    target.mac,
                    _confirmation(target, "signal"),
                    _auth(),
                    _config(),
                )
            )
    finally:
        transport.close()
    assert device.name == DEVICE.name


def test_revalidation_falls_back_to_a_filtered_multicast_identify():
    """A target that ignores unicast Identify is still revalidated by name+MAC."""
    device = default_mock_devices()[0]
    transport, writer, target = _setup_with_network(_UnicastDeafNetwork([device]))
    try:
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=True,
                target_name=target.name_of_station,
            )
        )
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert result.verification == "verified"
    assert device.name == "line-77.tested"
    assert result.before_identity is not None
    assert any("NameOfStation-filtered multicast Identify" in w for w in result.warnings)
    identify_details = [
        t.detail for t in result.transactions if t.event == "identify_request"
    ]
    assert any("unicast to" in detail for detail in identify_details)
    assert any("NameOfStation filter" in detail for detail in identify_details)
    # Exactly one Set frame; the fallback is read-only.
    assert [t.event for t in result.transactions].count("set_request") == 1


def test_without_a_station_name_a_unicast_deaf_target_stays_unverified():
    device = default_mock_devices()[0]
    original_name = device.name
    transport, writer, target = _setup_with_network(_UnicastDeafNetwork([device]))
    try:
        result = writer.execute(
            WriteRequest(
                "set_name",
                target.mac,
                _confirmation(target),
                _auth(),
                _config(),
                name="line-77.tested",
                permanent=True,
            )
        )
    finally:
        transport.close()
    assert result.state == "target_unverified"
    assert result.transmitted is False
    assert result.request_frame_hex == ""
    assert device.name == original_name


@pytest.mark.parametrize("mode", [3, 9])
def test_reset_modes_3_and_9_are_guarded_and_acknowledged(mode):
    device, transport, _, _, writer, _, target = _setup()
    try:
        result = writer.execute(
            WriteRequest(
                "reset",
                target.mac,
                _confirmation(target, "reset"),
                _auth(),
                _config(),
                reset_mode=mode,
            )
        )
    finally:
        transport.close()
    assert result.state == "acknowledged"
    assert result.block_qualifier == mode << 1
    # p-net semantics: every mode >= 3 resets application and communication data.
    assert device.name == ""


def test_post_check_polls_within_the_recheck_window():
    device = default_mock_devices()[0]
    transport, writer, target = _setup_with_network(MockNetwork([device]))
    try:
        result = writer.execute(
            WriteRequest(
                "reset",
                target.mac,
                _confirmation(target, "reset"),
                _auth(),
                _config(),
                reset_mode=8,
            )
        )
        assert result.state == "acknowledged"
        # Two Identify requests per attempt (unicast + fallback): drop the first
        # four so the device answers on the third attempt.
        transport.network = _DropIdentifyNetwork([device], drop=4)
        result = writer.post_check(
            result, timeout_s=0.5, recheck_window_s=5.0
        )
    finally:
        transport.close()
    assert result.post_check_state == "responded"
    assert "attempt 3" in result.post_check_detail


def test_post_check_reports_no_response_after_the_window():
    device = default_mock_devices()[0]
    transport, writer, target = _setup_with_network(MockNetwork([device]))
    try:
        result = writer.execute(
            WriteRequest(
                "reset",
                target.mac,
                _confirmation(target, "reset"),
                _auth(),
                _config(),
                reset_mode=8,
            )
        )
        assert result.state == "acknowledged"
        transport.network = _SilentIdentifyNetwork([device])
        result = writer.post_check(
            result, timeout_s=0.5, recheck_window_s=2.5
        )
    finally:
        transport.close()
    assert result.post_check_state == "no_response"
    assert "outcome unknown" in result.post_check_detail
    assert "attempts" in result.post_check_detail


def test_post_check_falls_back_to_a_multicast_identify():
    device = default_mock_devices()[0]
    transport, writer, target = _setup_with_network(MockNetwork([device]))
    try:
        result = writer.execute(
            WriteRequest(
                "reset",
                target.mac,
                _confirmation(target, "reset"),
                _auth(),
                _config(),
                reset_mode=8,
            )
        )
        assert result.state == "acknowledged"
        transport.network = _UnicastDeafNetwork([device])
        result = writer.post_check(result, timeout_s=0.5)
    finally:
        transport.close()
    assert result.post_check_state == "responded"
    assert "multicast Identify for the same MAC" in result.post_check_detail
