from __future__ import annotations

import pytest

from dcpstudio.transport import interfaces as interfaces_module
from dcpstudio.transport import scapy_transport as module
from dcpstudio.transport.base import CaptureNotStarted, InterfaceInfo, TransportError
from dcpstudio.transport.interfaces import (
    MOCK_INTERFACE,
    enumerate_interfaces,
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
