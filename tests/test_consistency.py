from __future__ import annotations

from datetime import UTC, datetime

from dcpstudio.mock import MockDeviceConfig, MockNetwork, MockTransport
from dcpstudio.model import (
    DeviceIdentity,
    DiscoveryResult,
    find_address_conflicts,
)
from dcpstudio.services.discovery import DiscoveryConfig, DiscoveryService

NOW = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)


def _device(
    mac: str, *, name: str | None = None, ip: str | None = None
) -> DeviceIdentity:
    return DeviceIdentity(
        interface_id="mock",
        mac=mac,
        first_seen=NOW,
        last_seen=NOW,
        name_of_station=name,
        ip_address=ip,
    )


def _result(devices: list[DeviceIdentity]) -> DiscoveryResult:
    return DiscoveryResult(
        interface_id="mock",
        xid=0x12345678,
        started_at=NOW,
        finished_at=NOW,
        timeout_s=1.0,
        response_delay_factor=50,
        vlan_id=None,
        devices=devices,
    )


def test_unique_addresses_produce_no_conflict():
    devices = [
        _device("02:00:00:00:00:01", name="line-01", ip="192.0.2.11"),
        _device("02:00:00:00:00:02", name="line-02", ip="192.0.2.12"),
    ]
    assert find_address_conflicts(devices) == []


def test_duplicate_name_is_reported_with_sorted_macs():
    devices = [
        _device("02:00:00:00:00:02", name="line-01", ip="192.0.2.12"),
        _device("02:00:00:00:00:01", name="line-01", ip="192.0.2.11"),
    ]
    conflicts = find_address_conflicts(devices)
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict.kind == "duplicate_name"
    assert conflict.value == "line-01"
    assert conflict.macs == ("02:00:00:00:00:01", "02:00:00:00:00:02")
    assert "NameOfStation 'line-01'" in conflict.detail


def test_duplicate_ip_is_reported():
    devices = [
        _device("02:00:00:00:00:01", name="line-01", ip="192.0.2.50"),
        _device("02:00:00:00:00:02", name="line-02", ip="192.0.2.50"),
    ]
    conflicts = find_address_conflicts(devices)
    assert len(conflicts) == 1
    assert conflicts[0].kind == "duplicate_ip"
    assert conflicts[0].value == "192.0.2.50"
    assert "IPv4 parameter '192.0.2.50'" in conflicts[0].detail


def test_missing_name_and_zero_ip_are_not_duplicates():
    devices = [
        _device("02:00:00:00:00:01"),
        _device("02:00:00:00:00:02", name="", ip="0.0.0.0"),
        _device("02:00:00:00:00:03", name=None, ip=None),
    ]
    assert find_address_conflicts(devices) == []


def test_both_conflict_kinds_are_sorted_together():
    devices = [
        _device("02:00:00:00:00:02", name="b", ip="192.0.2.9"),
        _device("02:00:00:00:00:01", name="a", ip="192.0.2.9"),
        _device("02:00:00:00:00:03", name="b", ip="192.0.2.10"),
    ]
    conflicts = find_address_conflicts(devices)
    assert [conflict.kind for conflict in conflicts] == [
        "duplicate_ip",
        "duplicate_name",
    ]


def test_discovery_result_ignores_devices_that_answered_after_the_timeout():
    late = _device("02:00:00:00:00:02", name="line-01", ip="192.0.2.12")
    late.warnings.append("Response arrived after the configured timeout")
    result = _result([_device("02:00:00:00:00:01", name="line-01", ip="192.0.2.11"), late])
    assert result.address_conflicts == []


def test_discovery_warns_about_duplicate_addresses():
    devices = [
        MockDeviceConfig(mac="02:00:00:00:00:31", name="line-05", ip="192.0.2.31"),
        MockDeviceConfig(mac="02:00:00:00:00:32", name="line-05", ip="192.0.2.32"),
    ]
    transport = MockTransport(MockNetwork(devices))
    transport.start_capture()
    service = DiscoveryService(transport)
    transport.set_frame_callback(
        lambda raw, ts, direction: service.process_frame(raw, ts, direction)
    )
    try:
        result = service.discover(DiscoveryConfig(timeout_s=0.5))
    finally:
        transport.close()
    assert len(result.devices) == 2
    assert any("duplicate NameOfStation 'line-05'" in w for w in result.warnings)
    assert len(result.address_conflicts) == 1
