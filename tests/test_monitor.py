"""Monitor diff and loop tests (no Qt, no network)."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from types import SimpleNamespace

from dcpstudio.model import DeviceIdentity, DiscoveryResult
from dcpstudio.monitor import (
    MonitorChangeKind,
    MonitorConfig,
    MonitorRun,
    diff_snapshots,
    snapshot_of,
)
from dcpstudio.services.monitor import MonitorService

T0 = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)


def _device(
    mac: str = "02:00:00:00:00:11",
    *,
    name: str | None = "device-1",
    ip: str | None = "192.168.20.11",
    vendor: int | None = 0x002A,
) -> DeviceIdentity:
    return DeviceIdentity(
        interface_id="mock:demo0",
        mac=mac,
        first_seen=T0,
        last_seen=T0,
        name_of_station=name,
        ip_address=ip,
        subnet_mask="255.255.255.0",
        gateway="192.168.20.1",
        vendor_id=vendor,
        device_id=0x0001,
        device_role_flags=0x01,
    )


def test_diff_reports_added_removed_and_changed_fields():
    first = snapshot_of([_device()])
    second = snapshot_of(
        [
            _device(name="renamed", ip="192.168.20.12"),
            _device(mac="02:00:00:00:00:22", name="new-device"),
        ]
    )
    changes = diff_snapshots(first, second, timestamp=T0)
    kinds = [str(change.kind) for change in changes]
    assert MonitorChangeKind.CHANGED in kinds
    assert MonitorChangeKind.ADDED in kinds
    changed = [c for c in changes if c.kind == MonitorChangeKind.CHANGED]
    assert [c.field for c in changed] == ["name_of_station", "ip_address"]
    assert changed[0].before == "device-1" and changed[0].after == "renamed"
    assert changed[0].field_label == "NameOfStation"
    added = next(c for c in changes if c.kind == MonitorChangeKind.ADDED)
    assert added.mac == "02:00:00:00:00:22"


def test_diff_reports_removals_and_ignores_volatile_fields():
    before = _device()
    after = _device()
    after.last_seen = datetime(2026, 11, 19, 10, 5, tzinfo=UTC)
    after.response_count = 9
    after.response_time_ms = 12.5
    assert diff_snapshots(snapshot_of([before]), snapshot_of([after]), timestamp=T0) == []

    removed = diff_snapshots(snapshot_of([before]), {}, timestamp=T0)
    assert len(removed) == 1
    assert removed[0].kind == MonitorChangeKind.REMOVED
    assert "disappeared" in removed[0].text


def _result(devices: list[DeviceIdentity], *, error: str | None = None) -> DiscoveryResult:
    return DiscoveryResult(
        interface_id="mock:demo0",
        xid=0x1234,
        started_at=T0,
        finished_at=T0,
        timeout_s=0.5,
        response_delay_factor=1,
        vlan_id=None,
        devices=devices,
        error=error,
    )


class _FakeDiscovery:
    def __init__(self, results: list[DiscoveryResult]) -> None:
        self.results = results
        self.calls = 0
        self.limiter = SimpleNamespace(min_interval_s=0.0)
        self.transport = SimpleNamespace(interface=SimpleNamespace(id="mock:demo0"))

    def discover(self, config, *, cancel_event=None, progress=None):  # noqa: ANN001
        index = min(self.calls, len(self.results) - 1)
        self.calls += 1
        return self.results[index]


def test_monitor_service_runs_configured_cycles_and_collects_changes():
    discovery = _FakeDiscovery(
        [
            _result([_device()]),
            _result([_device(name="renamed")]),
            _result([_device(name="renamed")]),
        ]
    )
    seen = []
    service = MonitorService(discovery)
    run = service.run(
        MonitorConfig(interval_s=0.0, timeout_s=0.5, response_delay_factor=1, cycles=3),
        on_cycle=seen.append,
    )
    assert len(run.cycles) == 3
    assert [c.index for c in run.cycles] == [0, 1, 2]
    assert len(seen) == 3
    assert len(run.cycles[0].changes) == 1  # first cycle: the device appeared
    assert run.cycles[1].changes[0].field == "name_of_station"
    assert run.cycles[2].changes == ()
    assert discovery.calls == 3
    assert run.cancelled is False and run.error is None


def test_monitor_service_stops_on_discovery_error():
    discovery = _FakeDiscovery([_result([], error="capture failed")])
    run = MonitorService(discovery).run(
        MonitorConfig(interval_s=0.0, timeout_s=0.5, response_delay_factor=1, cycles=5)
    )
    assert len(run.cycles) == 1
    assert run.error == "capture failed"
    assert discovery.calls == 1


def test_monitor_service_stops_when_cancelled_before_first_cycle():
    discovery = _FakeDiscovery([_result([_device()])])
    cancel = threading.Event()
    cancel.set()
    run = MonitorService(discovery).run(
        MonitorConfig(interval_s=0.0, timeout_s=0.5, response_delay_factor=1, cycles=0),
        cancel_event=cancel,
    )
    assert run.cycles == []
    assert run.cancelled is True
    assert discovery.calls == 0


def test_monitor_run_json_payload_is_serialisable():
    run = MonitorRun(interface_id="mock:demo0", config=MonitorConfig(cycles=1))
    payload = json.loads(json.dumps(run.to_dict(), default=str))
    assert payload["interface"] == "mock:demo0"
    assert payload["config"]["cycles"] == 1
    assert payload["changes"] == []
