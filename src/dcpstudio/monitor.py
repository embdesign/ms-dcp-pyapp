"""Repeated-Identify monitoring: configuration, snapshots and change diffs.

The monitor is a *read-only* engineering view: it repeats the ordinary Identify
request at a user-chosen interval and compares each cycle's device identities
with the previous one. It introduces no new wire format — every cycle is one
normal Identify transaction handled by :class:`~dcpstudio.services.discovery.
DiscoveryService`.

This module is pure: it only compares :class:`~dcpstudio.model.DeviceIdentity`
values and renders strings. The loop lives in
:mod:`dcpstudio.services.monitor`.

Types of change (``MonitorChangeKind``) are deliberately separate from the
operation outcome vocabulary in :mod:`dcpstudio.outcomes`; "added" or "removed"
is not the result of a request.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from .constants import DEFAULT_RESPONSE_DELAY_FACTOR
from .model import DeviceIdentity, iso_utc, utc_now

MIN_MONITOR_INTERVAL_S = 1.0
MAX_MONITOR_INTERVAL_S = 3600.0
MAX_MONITOR_CYCLES = 10000

# Identity attributes whose change is reported. Response timing, counters and
# raw frames change every cycle and would drown the engineering signal.
MONITORED_FIELDS: tuple[str, ...] = (
    "name_of_station",
    "ip_address",
    "subnet_mask",
    "gateway",
    "vendor_id",
    "device_id",
    "device_role_flags",
    "alias",
    "device_instance",
    "oem_vendor_id",
    "oem_device_id",
    "device_options",
)

MONITORED_FIELD_LABELS: dict[str, str] = {
    "name_of_station": "NameOfStation",
    "ip_address": "IP address",
    "subnet_mask": "Subnet mask",
    "gateway": "Gateway",
    "vendor_id": "Vendor ID",
    "device_id": "Device ID",
    "device_role_flags": "Device role",
    "alias": "Alias name",
    "device_instance": "Device instance",
    "oem_vendor_id": "OEM vendor ID",
    "oem_device_id": "OEM device ID",
    "device_options": "DCP options",
}


class MonitorChangeKind(StrEnum):
    """How one device differs from the previous monitor cycle."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


@dataclass(slots=True, frozen=True)
class MonitorConfig:
    """One monitor run.

    ``cycles = 0`` means "until cancelled". ``interval_s`` is the minimum time
    between the *starts* of two cycles; the shared request limiter may stretch
    it further.
    """

    interval_s: float = 5.0
    timeout_s: float = 3.0
    response_delay_factor: int = DEFAULT_RESPONSE_DELAY_FACTOR
    vlan_id: int | None = None
    cycles: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "interval_s": self.interval_s,
            "timeout_s": self.timeout_s,
            "response_delay_factor": self.response_delay_factor,
            "vlan_id": self.vlan_id,
            "cycles": self.cycles,
        }


@dataclass(slots=True)
class DeviceChange:
    """One added, removed or modified device in a monitor cycle."""

    kind: MonitorChangeKind
    timestamp: datetime
    interface_id: str
    mac: str
    name_of_station: str | None
    field: str | None = None
    before: str | None = None
    after: str | None = None

    @property
    def device_text(self) -> str:
        return self.name_of_station or "<not set>"

    @property
    def field_label(self) -> str:
        if self.field is None:
            return ""
        return MONITORED_FIELD_LABELS.get(self.field, self.field)

    @property
    def text(self) -> str:
        if self.kind == MonitorChangeKind.ADDED:
            return f"{self.mac} appeared ({self.device_text})"
        if self.kind == MonitorChangeKind.REMOVED:
            return f"{self.mac} disappeared ({self.device_text})"
        return f"{self.mac} {self.field_label}: {self.before} → {self.after}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": str(self.kind),
            "timestamp": iso_utc(self.timestamp),
            "interface": self.interface_id,
            "mac": self.mac,
            "name_of_station": self.name_of_station,
            "field": self.field,
            "field_label": self.field_label,
            "before": self.before,
            "after": self.after,
            "text": self.text,
        }


@dataclass(slots=True)
class MonitorCycle:
    """The outcome of one Identify pass and its diff against the previous one."""

    index: int
    started_at: datetime
    finished_at: datetime
    outcome: str
    outcome_text: str
    devices: tuple[DeviceIdentity, ...] = ()
    changes: tuple[DeviceChange, ...] = ()
    warnings: tuple[str, ...] = ()
    error: str | None = None

    @property
    def device_count(self) -> int:
        return len(self.devices)

    @property
    def duration_ms(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds() * 1000.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "started_at": iso_utc(self.started_at),
            "finished_at": iso_utc(self.finished_at),
            "duration_ms": round(self.duration_ms, 3),
            "outcome": self.outcome,
            "outcome_text": self.outcome_text,
            "device_count": self.device_count,
            "devices": [device.to_dict() for device in self.devices],
            "changes": [change.to_dict() for change in self.changes],
            "warnings": list(self.warnings),
            "error": self.error,
        }


@dataclass(slots=True)
class MonitorRun:
    """All cycles of one monitor run."""

    interface_id: str
    config: MonitorConfig
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    cycles: list[MonitorCycle] = field(default_factory=list)
    cancelled: bool = False
    error: str | None = None

    @property
    def changes(self) -> list[DeviceChange]:
        return [change for cycle in self.cycles for change in cycle.changes]

    @property
    def last_cycle(self) -> MonitorCycle | None:
        return self.cycles[-1] if self.cycles else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface_id,
            "config": self.config.to_dict(),
            "started_at": iso_utc(self.started_at),
            "finished_at": iso_utc(self.finished_at),
            "cycles": [cycle.to_dict() for cycle in self.cycles],
            "changes": [change.to_dict() for change in self.changes],
            "cancelled": self.cancelled,
            "error": self.error,
        }


def _format_value(identity: DeviceIdentity, field_name: str) -> str:
    value = getattr(identity, field_name)
    if field_name in ("vendor_id", "device_id", "oem_vendor_id", "oem_device_id"):
        return "not advertised" if value is None else f"0x{value:04x}"
    if field_name == "device_role_flags":
        return identity.role_text
    if field_name == "device_options":
        return identity.options_text
    if field_name == "device_instance":
        return "not advertised" if value is None else f"{value[0]}/{value[1]}"
    return "<not set>" if value is None else str(value)


def diff_snapshots(
    previous: Mapping[tuple[str, str], DeviceIdentity],
    current: Mapping[tuple[str, str], DeviceIdentity],
    *,
    timestamp: datetime | None = None,
) -> list[DeviceChange]:
    """Compare two ``(interface, MAC) -> identity`` snapshots.

    Devices are compared on the fields in ``MONITORED_FIELDS`` only; volatile
    fields (last-seen time, response counters, raw frames) are ignored. The
    result is sorted by MAC and field order, so logs and tests are stable.
    """
    at = timestamp or utc_now()
    changes: list[DeviceChange] = []
    for key in sorted(set(previous) | set(current)):
        before = previous.get(key)
        after = current.get(key)
        interface_id, mac = key
        if before is None and after is not None:
            changes.append(
                DeviceChange(
                    kind=MonitorChangeKind.ADDED,
                    timestamp=at,
                    interface_id=interface_id,
                    mac=mac,
                    name_of_station=after.name_of_station,
                )
            )
            continue
        if before is not None and after is None:
            changes.append(
                DeviceChange(
                    kind=MonitorChangeKind.REMOVED,
                    timestamp=at,
                    interface_id=interface_id,
                    mac=mac,
                    name_of_station=before.name_of_station,
                )
            )
            continue
        if before is None or after is None:  # pragma: no cover - both are known
            continue
        for field_name in MONITORED_FIELDS:
            if getattr(before, field_name) == getattr(after, field_name):
                continue
            changes.append(
                DeviceChange(
                    kind=MonitorChangeKind.CHANGED,
                    timestamp=at,
                    interface_id=interface_id,
                    mac=mac,
                    name_of_station=after.name_of_station,
                    field=field_name,
                    before=_format_value(before, field_name),
                    after=_format_value(after, field_name),
                )
            )
    return changes


def snapshot_of(devices: Any) -> dict[tuple[str, str], DeviceIdentity]:
    """Build the diff key for an iterable of identities."""
    return {(device.interface_id, device.mac): device for device in devices}
