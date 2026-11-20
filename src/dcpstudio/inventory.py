"""Device inventory export and as-planned comparison.

Pure functions only: no Qt, no network, no I/O. Discovery produces
:class:`DeviceIdentity` objects; this module turns them into a CSV inventory,
parses a plan file and compares the two so a commissioning engineer can show
"as found" versus "as planned".

The plan is a plain CSV with a header row. Recognised columns are ``mac``,
``name_of_station``, ``ip_address``, ``subnet_mask`` and ``gateway`` (aliases
such as ``name`` or ``ip`` are accepted). A row identifies a device by MAC, by
NameOfStation, or by both; comparisons are exact and case-sensitive, matching
the DCP NameOfStation filter.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .codec import parse_mac
from .model import DeviceIdentity, iso_utc

INVENTORY_COLUMNS: tuple[str, ...] = (
    "mac",
    "name_of_station",
    "ip_address",
    "subnet_mask",
    "gateway",
    "vendor_id",
    "device_id",
    "vendor_name",
    "role",
    "dcp_options",
    "alias",
    "device_instance",
    "interface_id",
    "last_seen_utc",
)

PLAN_COLUMNS: tuple[str, ...] = (
    "mac",
    "name_of_station",
    "ip_address",
    "subnet_mask",
    "gateway",
)

_HEADER_ALIASES: dict[str, str] = {
    "mac": "mac",
    "mac_address": "mac",
    "name": "name_of_station",
    "nameofstation": "name_of_station",
    "name_of_station": "name_of_station",
    "station_name": "name_of_station",
    "ip": "ip_address",
    "ipaddress": "ip_address",
    "ip_address": "ip_address",
    "mask": "subnet_mask",
    "subnet_mask": "subnet_mask",
    "subnetmask": "subnet_mask",
    "gateway": "gateway",
    "gw": "gateway",
}

# Finding vocabulary. ``kind`` is a stable identifier used by the CLI/JSON.
FINDING_MISSING_DEVICE = "missing_device"
FINDING_UNEXPECTED_DEVICE = "unexpected_device"
FINDING_AMBIGUOUS_MATCH = "ambiguous_match"
FINDING_NAME_MISMATCH = "name_mismatch"
FINDING_IP_MISMATCH = "ip_mismatch"
FINDING_MASK_MISMATCH = "mask_mismatch"
FINDING_GATEWAY_MISMATCH = "gateway_mismatch"


def _text(value: str | None) -> str:
    return (value or "").strip()


def _mac(value: str | None) -> str:
    return _text(value).replace("-", ":").lower()


def inventory_rows(devices: Iterable[DeviceIdentity]) -> list[dict[str, str]]:
    """One flat row per device, in the order given."""
    rows: list[dict[str, str]] = []
    for device in devices:
        instance = (
            f"{device.device_instance[0]}/{device.device_instance[1]}"
            if device.device_instance
            else ""
        )
        rows.append(
            {
                "mac": device.mac,
                "name_of_station": _text(device.name_of_station),
                "ip_address": _text(device.ip_address),
                "subnet_mask": _text(device.subnet_mask),
                "gateway": _text(device.gateway),
                "vendor_id": (
                    f"0x{device.vendor_id:04x}" if device.vendor_id is not None else ""
                ),
                "device_id": (
                    f"0x{device.device_id:04x}" if device.device_id is not None else ""
                ),
                "vendor_name": _text(device.vendor_name),
                "role": device.role_text,
                "dcp_options": device.options_text,
                "alias": _text(device.alias),
                "device_instance": instance,
                "interface_id": device.interface_id,
                "last_seen_utc": iso_utc(device.last_seen) or "",
            }
        )
    return rows


def inventory_csv(devices: Iterable[DeviceIdentity]) -> str:
    """CSV text for the discovered devices (header always present)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=list(INVENTORY_COLUMNS), lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(inventory_rows(devices))
    return buffer.getvalue()


def device_matches_filter(
    device: DeviceIdentity,
    query: str,
    *,
    uncommissioned_only: bool = False,
) -> bool:
    """True when a device passes the device-table filter.

    Every whitespace-separated query token must occur somewhere in the MAC,
    NameOfStation, IP, vendor name or interface id (case-insensitive).
    "Uncommissioned" means the device advertises no NameOfStation.
    """
    if uncommissioned_only and device.name_of_station:
        return False
    tokens = query.lower().split()
    if not tokens:
        return True
    haystack = " ".join(
        (
            device.mac,
            device.name_of_station or "",
            device.ip_address or "",
            device.vendor_name or "",
            device.interface_id,
        )
    ).lower()
    return all(token in haystack for token in tokens)


@dataclass(frozen=True, slots=True)
class PlanEntry:
    """One expected device from a plan file; empty fields are not compared."""

    mac: str = ""
    name_of_station: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    gateway: str = ""

    @property
    def label(self) -> str:
        return self.name_of_station or self.mac or "<unnamed plan row>"

    def to_dict(self) -> dict[str, str]:
        return {
            "mac": self.mac,
            "name_of_station": self.name_of_station,
            "ip_address": self.ip_address,
            "subnet_mask": self.subnet_mask,
            "gateway": self.gateway,
        }


@dataclass(frozen=True, slots=True)
class PlanFinding:
    """One difference between the plan and the discovered segment."""

    kind: str
    subject: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "subject": self.subject, "detail": self.detail}


def _normalize_header(value: str) -> str:
    return value.strip().lower().replace(" ", "_").replace("-", "_")


def parse_plan_csv(text: str) -> tuple[list[PlanEntry], list[str]]:
    """Parse a plan CSV into entries plus operator-readable warnings.

    Blank lines and ``#`` comment lines are ignored. A row needs a MAC or a
    NameOfStation; an invalid MAC is reported and skipped rather than guessed.
    """
    warnings: list[str] = []
    lines = [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        return [], ["The plan file is empty."]
    reader = csv.DictReader(lines, skipinitialspace=True)
    if not reader.fieldnames:
        return [], ["The plan file has no header row."]
    canonical: dict[str, str] = {}
    for raw in reader.fieldnames:
        key = _HEADER_ALIASES.get(_normalize_header(raw))
        if key is None:
            warnings.append(f"Ignoring unknown plan column {raw!r}.")
        else:
            canonical[raw] = key
    if not {"mac", "name_of_station"} & set(canonical.values()):
        warnings.append(
            "The plan needs at least a 'mac' or 'name_of_station' column."
        )
        return [], warnings
    entries: list[PlanEntry] = []
    for line_number, row in enumerate(reader, start=2):
        values = {
            canonical[raw]: _text(value)
            for raw, value in row.items()
            if raw in canonical and isinstance(value, str)
        }
        mac = _mac(values.get("mac"))
        if not mac and not values.get("name_of_station"):
            warnings.append(
                f"Plan row {line_number} has neither MAC nor NameOfStation; skipped."
            )
            continue
        if mac:
            try:
                parse_mac(mac)
            except ValueError as exc:
                warnings.append(
                    f"Plan row {line_number}: invalid MAC {values['mac']!r} ({exc}); skipped."
                )
                continue
        entries.append(
            PlanEntry(
                mac=mac,
                name_of_station=values.get("name_of_station", ""),
                ip_address=values.get("ip_address", ""),
                subnet_mask=values.get("subnet_mask", ""),
                gateway=values.get("gateway", ""),
            )
        )
    if not entries and not warnings:
        warnings.append("The plan contains no device rows.")
    return entries, warnings


def compare_plan(
    devices: Sequence[DeviceIdentity], plan: Sequence[PlanEntry]
) -> list[PlanFinding]:
    """Compare discovered devices with the plan, sorted for stable output.

    An empty plan compares nothing and returns no findings. Each plan row is
    matched by MAC when given, otherwise by exact NameOfStation. Fields present
    in the plan must match exactly; discovered devices that no plan row matched
    are reported as unexpected.
    """
    if not plan:
        return []
    by_mac = {_mac(device.mac): device for device in devices}
    by_name: dict[str, list[DeviceIdentity]] = {}
    for device in devices:
        if device.name_of_station:
            by_name.setdefault(device.name_of_station, []).append(device)

    findings: list[PlanFinding] = []
    matched: set[str] = set()
    for entry in plan:
        device: DeviceIdentity | None = None
        if entry.mac:
            device = by_mac.get(entry.mac)
        elif entry.name_of_station:
            candidates = by_name.get(entry.name_of_station, [])
            if len(candidates) > 1:
                macs = ", ".join(sorted(_mac(item.mac) for item in candidates))
                findings.append(
                    PlanFinding(
                        FINDING_AMBIGUOUS_MATCH,
                        entry.label,
                        f"NameOfStation {entry.name_of_station!r} is advertised by "
                        f"{macs}; the plan entry cannot identify one device.",
                    )
                )
                matched.update(_mac(item.mac) for item in candidates)
                continue
            device = candidates[0] if candidates else None
        if device is None:
            findings.append(
                PlanFinding(
                    FINDING_MISSING_DEVICE,
                    entry.label,
                    f"Plan entry {entry.label!r} was not discovered on the segment.",
                )
            )
            continue
        matched.add(_mac(device.mac))
        checks = (
            (FINDING_NAME_MISMATCH, "NameOfStation", entry.name_of_station, device.name_of_station),
            (FINDING_IP_MISMATCH, "IPv4 address", entry.ip_address, device.ip_address),
            (FINDING_MASK_MISMATCH, "subnet mask", entry.subnet_mask, device.subnet_mask),
            (FINDING_GATEWAY_MISMATCH, "gateway", entry.gateway, device.gateway),
        )
        for kind, label, expected, actual in checks:
            if not expected or _text(actual) == expected:
                continue
            findings.append(
                PlanFinding(
                    kind,
                    device.mac,
                    f"{device.mac} advertises {label} {_text(actual) or '<not set>'!r}, "
                    f"plan expects {expected!r}.",
                )
            )
    for device in devices:
        if _mac(device.mac) not in matched:
            findings.append(
                PlanFinding(
                    FINDING_UNEXPECTED_DEVICE,
                    device.mac,
                    f"{device.mac} ({device.display_name}) is on the segment but not "
                    "in the plan.",
                )
            )
    findings.sort(key=lambda finding: (finding.kind, finding.subject))
    return findings
