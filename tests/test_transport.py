from __future__ import annotations

import pytest

from dcpstudio.transport import interfaces as interfaces_module
from dcpstudio.transport import scapy_transport as module
from dcpstudio.transport.base import CaptureNotStarted, InterfaceInfo, TransportError
from dcpstudio.transport.interfaces import (
    MOCK_INTERFACE,
    enumerate_interfaces,
    find_interface,
    platform_label,
    raw_socket_privileges,
)
from dcpstudio.transport.scapy_transport import ScapyTransport


def _interface(**kwargs) -> InterfaceInfo:
    defaults = dict(
        id="eth-test",
        name="eth-test",
        description="Test NIC",
        mac="02:00:00:00:00:99",
        ipv4_addresses=("192.0.2.99",),
        is_up=True,
        is_running=True,
        kind="physical",
    )
    defaults.update(kwargs)
    return InterfaceInfo(**defaults)


def test_interface_enumeration_always_includes_mock():
    interfaces = enumerate_interfaces(include_mock=True)
    assert interfaces[0].id == MOCK_INTERFACE.id
    ids = [i.id for i in interfaces]
    assert len(ids) == len(set(ids))
    assert platform_label()


def test_raw_socket_privileges_returns_explanation():
    ok, text = raw_socket_privileges()
    assert isinstance(ok, bool)
    assert text


def test_readiness_ready_when_privileges_and_driver_are_available(monkeypatch):
    monkeypatch.setattr(module, "raw_socket_privileges", lambda: (True, "test root"))
    monkeypatch.setattr(module, "capture_driver_status", lambda: (True, "test driver"))
    transport = ScapyTransport(_interface())
    readiness = transport.readiness()
    assert readiness.ready is True
    assert "test root" in readiness.message
    transport.close()


def test_readiness_reports_missing_mac(monkeypatch):
    monkeypatch.setattr(module, "raw_socket_privileges", lambda: (True, "test root"))
    monkeypatch.setattr(module, "capture_driver_status", lambda: (True, "test driver"))
    transport = ScapyTransport(_interface(mac=None))
    readiness = transport.readiness()
    assert readiness.ready is False
    assert "no MAC" in readiness.message
    transport.close()


def test_send_before_capture_is_refused():
    transport = ScapyTransport(_interface())
    with pytest.raises(CaptureNotStarted):
        transport.send_frame(b"\x00" * 60)
    transport.close()


def test_mock_interface_is_rejected_by_scapy_transport():
    transport = ScapyTransport(MOCK_INTERFACE)
    with pytest.raises(TransportError):
        transport.start_capture()
    transport.close()


def test_start_capture_reports_privilege_failure(monkeypatch):
    monkeypatch.setattr(module, "raw_socket_privileges", lambda: (False, "no CAP_NET_RAW"))
    monkeypatch.setattr(module, "capture_requires_elevation", lambda: True)
    monkeypatch.setattr(module, "capture_driver_status", lambda: (True, "driver"))
    transport = ScapyTransport(_interface())
    with pytest.raises(TransportError) as excinfo:
        transport.start_capture()
    assert "not permitted" in str(excinfo.value).lower()
    transport.close()


def test_readiness_does_not_require_elevation_when_driver_allows_it(monkeypatch):
    # Windows/Npcap can capture as a normal user; the process rights are
    # reported but must not mark the interface as not ready.
    monkeypatch.setattr(module, "raw_socket_privileges", lambda: (False, "Not running as Administrator"))
    monkeypatch.setattr(module, "capture_requires_elevation", lambda: False)
    monkeypatch.setattr(module, "capture_driver_status", lambda: (True, "Npcap active"))
    transport = ScapyTransport(_interface())
    readiness = transport.readiness()
    assert readiness.ready is True
    assert "Npcap active" in readiness.message
    transport.close()


# ---------------------------------------------------------------- link state
# Scapy reports libpcap ``pcap_if_t.flags`` on Windows/Npcap as symbolic
# FlagValue names. Their bit positions are PCAP_IF_* values, not POSIX IFF_*.
_PCAP_FLAG_NAMES = ["LOOPBACK", "UP", "RUNNING", "WIRELESS", "OK", "DISCONNECTED", "NA"]


class _FakeIface:
    def __init__(self, flags: object) -> None:
        self.flags = flags


def _named_flags(*names: str) -> object:
    from scapy.fields import FlagValue

    return FlagValue([n for n in names], _PCAP_FLAG_NAMES)


def test_pcap_named_flags_report_running_nic_as_up():
    up, running, loopback = interfaces_module._link_state_from_flags(
        _FakeIface(_named_flags("UP", "RUNNING", "OK"))
    )
    assert (up, running, loopback) == (True, True, False)


def test_pcap_named_flags_do_not_treat_wireless_as_loopback():
    # PCAP_IF_WIRELESS is bit 0x8; reading POSIX IFF_LOOPBACK from it is wrong.
    up, running, loopback = interfaces_module._link_state_from_flags(
        _FakeIface(_named_flags("UP", "RUNNING", "WIRELESS", "OK"))
    )
    assert (up, running, loopback) == (True, True, False)


def test_pcap_named_flags_report_disconnected_nic_without_carrier():
    up, running, loopback = interfaces_module._link_state_from_flags(
        _FakeIface(_named_flags("UP", "RUNNING", "WIRELESS", "DISCONNECTED"))
    )
    assert up is True
    assert running is False
    assert loopback is False


def test_pcap_named_flags_detect_real_loopback():
    up, running, loopback = interfaces_module._link_state_from_flags(
        _FakeIface(_named_flags("LOOPBACK", "UP", "RUNNING", "OK", "DISCONNECTED"))
    )
    assert (up, running, loopback) == (True, True, True)


def test_posix_integer_flags_still_decode():
    # Linux/BSD report a plain struct ifreq bitmask.
    up, running, loopback = interfaces_module._link_state_from_flags(
        _FakeIface(0x1 | 0x40)
    )
    assert (up, running, loopback) == (True, True, False)
    up, running, loopback = interfaces_module._link_state_from_flags(
        _FakeIface(0x1 | 0x8)
    )
    assert (up, running, loopback) == (True, False, True)


# ------------------------------------------------- capture start/stop details
class _FakeSniffer:
    def __init__(self) -> None:
        self.running = True
        self.exception: object | None = None
        self.thread = None
        self.stopped = False

    def stop(self, join: bool = False) -> None:
        self.running = False
        self.stopped = True


def _allow_privileges(monkeypatch, *, driver: tuple[bool, str] = (True, "driver")) -> None:
    monkeypatch.setattr(module, "raw_socket_privileges", lambda: (True, "root"))
    monkeypatch.setattr(module, "capture_requires_elevation", lambda: True)
    monkeypatch.setattr(module, "capture_driver_status", lambda: driver)


def test_capture_falls_back_to_an_unfiltered_sniffer(monkeypatch):
    _allow_privileges(monkeypatch)
    sniffer = _FakeSniffer()
    attempts: list[bool] = []

    def fake_try_start(transport, sniffer_cls, *, with_filter, errors):
        attempts.append(with_filter)
        if with_filter:
            errors.append("filtered start: cannot compile BPF")
            return None
        transport.filter_ok = False
        transport.used_filter = ""
        return sniffer

    monkeypatch.setattr(ScapyTransport, "_try_start", fake_try_start)
    transport = ScapyTransport(_interface())
    transport.start_capture()
    try:
        assert attempts == [True, False]
        assert transport.is_capturing is True
        assert transport.filter_ok is False
        assert transport.used_filter == ""
    finally:
        transport.close()
    assert sniffer.stopped is True
    assert transport.is_capturing is False


def test_capture_reports_both_failed_attempts(monkeypatch):
    _allow_privileges(monkeypatch)

    def fake_try_start(transport, sniffer_cls, *, with_filter, errors):
        errors.append(f"{'filtered' if with_filter else 'unfiltered'} start: boom")
        return None

    monkeypatch.setattr(ScapyTransport, "_try_start", fake_try_start)
    transport = ScapyTransport(_interface())
    with pytest.raises(TransportError) as excinfo:
        transport.start_capture()
    assert "filtered start: boom" in str(excinfo.value)
    assert "unfiltered start: boom" in str(excinfo.value)
    transport.close()


def test_on_packet_uses_the_packet_timestamp_and_ignores_bad_packets():
    delivered: list[tuple[bytes, object, str]] = []
    transport = ScapyTransport(_interface())
    transport.set_frame_callback(lambda raw, ts, direction: delivered.append((raw, ts, direction)))

    class _Packet:
        time = 1234567890.5

        def __bytes__(self) -> bytes:
            return b"\x01\x02\x03"

    class _BrokenPacket:
        time = None

        def __bytes__(self) -> bytes:
            raise ValueError("cannot serialize")

    transport._on_packet(_Packet())
    transport._on_packet(_BrokenPacket())  # must not escape

    assert len(delivered) == 1
    raw, timestamp, direction = delivered[0]
    assert raw == b"\x01\x02\x03"
    assert direction == "rx"
    assert timestamp.year >= 2009
    transport.close()


# ------------------------------------------------------ readiness and lookup
def test_readiness_reports_a_missing_capture_driver(monkeypatch):
    _allow_privileges(monkeypatch, driver=(False, "Npcap is not installed"))
    transport = ScapyTransport(_interface())
    readiness = transport.readiness()
    assert readiness.ready is False
    assert "Npcap is not installed" in readiness.message
    transport.close()


def test_readiness_refuses_loopback_for_profinet(monkeypatch):
    _allow_privileges(monkeypatch)
    transport = ScapyTransport(_interface(is_loopback=True, kind="loopback"))
    readiness = transport.readiness()
    assert readiness.ready is False
    assert "Loopback" in readiness.message
    transport.close()


def test_find_interface_resolves_the_mock_and_rejects_unknown_ids():
    assert find_interface(MOCK_INTERFACE.id) is not None
    assert find_interface("no-such-interface") is None


def test_interface_enumeration_can_exclude_the_mock():
    ids = [item.id for item in enumerate_interfaces(include_mock=False)]
    assert MOCK_INTERFACE.id not in ids


def test_platform_label_includes_the_platform_token(monkeypatch):
    monkeypatch.setattr(interfaces_module, "_PLATFORM", "testos")
    monkeypatch.setattr(interfaces_module._platform, "system", lambda: "TestOS")
    monkeypatch.setattr(interfaces_module._platform, "release", lambda: "1.0")
    assert platform_label() == "TestOS 1.0 (testos)"
