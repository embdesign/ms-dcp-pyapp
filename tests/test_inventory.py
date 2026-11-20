"""Tests for the pure inventory export, filter and plan comparison."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from dcpstudio.inventory import (
    compare_plan,
    device_matches_filter,
    inventory_csv,
    inventory_rows,
    parse_plan_csv,
)
from dcpstudio.model import DeviceIdentity

NOW = datetime(2026, 11, 20, 9, 0, 0, tzinfo=UTC)


def _device(
    mac: str,
    *,
    name: str | None = None,
    ip: str | None = None,
    mask: str | None = None,
    gateway: str | None = None,
    vendor_name: str | None = "Mock Automation",
) -> DeviceIdentity:
    return DeviceIdentity(
        interface_id="mock",
        mac=mac,
        first_seen=NOW,
        last_seen=NOW,
        name_of_station=name,
        ip_address=ip,
        subnet_mask=mask,
        gateway=gateway,
        vendor_id=0x002A,
        device_id=0x0101,
        vendor_name=vendor_name,
        device_role_flags=0x01,
    )


DEVICES = [
    _device(
        "02:00:00:00:00:11",
        name="line-01.conveyor",
        ip="192.0.2.11",
        mask="255.255.255.0",
        gateway="192.0.2.1",
    ),
    _device(
        "02:00:00:00:00:12",
        name="line-01.robot",
        ip="192.0.2.12",
        mask="255.255.255.0",
        gateway="192.0.2.1",
    ),
    _device("02:00:00:00:00:13", name="", ip="0.0.0.0"),
]


# ------------------------------------------------------------------ inventory
def test_inventory_rows_flatten_the_device():
    rows = inventory_rows(DEVICES[:1])
    assert len(rows) == 1
    row = rows[0]
    assert row["mac"] == "02:00:00:00:00:11"
    assert row["name_of_station"] == "line-01.conveyor"
    assert row["ip_address"] == "192.0.2.11"
    assert row["vendor_id"] == "0x002a"
    assert row["device_id"] == "0x0101"
    assert row["role"] == "IO-Device"
    assert row["last_seen_utc"].endswith("Z")


def test_inventory_csv_roundtrips_through_csv_reader():
    text = inventory_csv(DEVICES)
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    assert reader.fieldnames == [
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
    ]
    assert [row["mac"] for row in rows] == [d.mac for d in DEVICES]


def test_inventory_csv_keeps_the_header_when_nothing_was_found():
    text = inventory_csv([])
    assert text.strip() == (
        "mac,name_of_station,ip_address,subnet_mask,gateway,vendor_id,device_id,"
        "vendor_name,role,dcp_options,alias,device_instance,interface_id,"
        "last_seen_utc"
    )


# --------------------------------------------------------------- table filter
def test_filter_matches_name_mac_and_ip_case_insensitively():
    assert device_matches_filter(DEVICES[0], "CONVEYOR")
    assert device_matches_filter(DEVICES[0], "00:11")
    assert device_matches_filter(DEVICES[0], "192.0.2.11")
    assert not device_matches_filter(DEVICES[1], "conveyor")


def test_filter_requires_every_token():
    assert device_matches_filter(DEVICES[0], "line 192.0.2.11")
    assert not device_matches_filter(DEVICES[0], "line 192.0.2.99")


def test_filter_uncommissioned_only_hides_named_devices():
    assert device_matches_filter(DEVICES[2], "", uncommissioned_only=True)
    assert not device_matches_filter(DEVICES[0], "", uncommissioned_only=True)
    assert device_matches_filter(DEVICES[0], "", uncommissioned_only=False)


def test_empty_filter_shows_everything():
    assert device_matches_filter(DEVICES[0], "   ")


# ---------------------------------------------------------------- plan parser
def test_plan_accepts_aliases_and_comments():
    entries, warnings = parse_plan_csv(
        "\n".join(
            [
                "# commissioning plan",
                "MAC,name,ip,mask,gw",
                "02:00:00:00:00:11,line-01.conveyor,192.0.2.11,255.255.255.0,192.0.2.1",
                "",
            ]
        )
    )
    assert warnings == []
    assert len(entries) == 1
    entry = entries[0]
    assert entry.mac == "02:00:00:00:00:11"
    assert entry.name_of_station == "line-01.conveyor"
    assert entry.ip_address == "192.0.2.11"
    assert entry.subnet_mask == "255.255.255.0"
    assert entry.gateway == "192.0.2.1"


def test_plan_skips_rows_without_identity_or_a_valid_mac():
    entries, warnings = parse_plan_csv(
        "mac,name\n,,,,,\nnot-a-mac,line-99\n"
    )
    assert entries == []
    assert any("neither MAC nor NameOfStation" in w for w in warnings)
    assert any("invalid MAC" in w for w in warnings)


def test_plan_requires_a_usable_header():
    entries, warnings = parse_plan_csv("")
    assert entries == []
    assert warnings == ["The plan file is empty."]
    entries, warnings = parse_plan_csv("foo,bar\n1,2\n")
    assert entries == []
    assert any("mac" in warning for warning in warnings)


# --------------------------------------------------------------- plan compare
def test_matching_plan_reports_nothing():
    plan = [
        # By MAC + all fields
        parse_plan_csv(
            "mac,name_of_station,ip_address,subnet_mask,gateway\n"
            "02:00:00:00:00:11,line-01.conveyor,192.0.2.11,255.255.255.0,192.0.2.1\n"
        )[0][0],
        # By name only
        parse_plan_csv("name_of_station\nline-01.robot\n")[0][0],
        # The uncommissioned device, by MAC only
        parse_plan_csv("mac\n02:00:00:00:00:13\n")[0][0],
    ]
    assert compare_plan(DEVICES, plan) == []


def test_missing_and_unexpected_devices_are_reported():
    plan = parse_plan_csv(
        "mac,name_of_station\n02:00:00:00:00:11,line-01.conveyor\n"
        "02:00:00:00:00:99,line-09.absent\n"
    )[0]
    findings = compare_plan(DEVICES, plan)
    kinds = [finding.kind for finding in findings]
    assert "missing_device" in kinds
    assert kinds.count("unexpected_device") == 2


def test_field_mismatches_use_specific_kinds():
    plan = parse_plan_csv(
        "mac,name,ip,mask,gw\n"
        "02:00:00:00:00:11,line-99.wrong,192.0.2.99,255.255.0.0,192.0.2.254\n"
    )[0]
    findings = compare_plan(DEVICES[:1], plan)
    kinds = sorted(finding.kind for finding in findings)
    assert kinds == [
        "gateway_mismatch",
        "ip_mismatch",
        "mask_mismatch",
        "name_mismatch",
    ]
    assert all("02:00:00:00:00:11" in finding.detail for finding in findings)


def test_ambiguous_name_does_not_also_report_missing():
    devices = [
        _device("02:00:00:00:00:01", name="line-01"),
        _device("02:00:00:00:00:02", name="line-01"),
    ]
    plan = parse_plan_csv("name_of_station\nline-01\n")[0]
    findings = compare_plan(devices, plan)
    assert [finding.kind for finding in findings] == ["ambiguous_match"]
    assert "02:00:00:00:00:01" in findings[0].detail


def test_empty_plan_compares_nothing():
    assert compare_plan(DEVICES, []) == []
