from __future__ import annotations

from dcpstudio.validation import (
    validate_ip_suite,
    validate_mac,
    validate_netmask,
    validate_response_delay_factor,
    validate_station_name,
    validate_vlan,
)


def test_valid_station_names():
    for name in ("line-01.conveyor", "a", "", "port-1.device", "a-b.c-d"):
        assert validate_station_name(name).ok, name


def test_invalid_station_names():
    for name in (
        "Line-01",
        "-device",
        "device-",
        "a..b",
        "192.168.1.10",
        "port-001",
        "port-001-00001",
        "a" * 241,
        "a" * 64,
    ):
        assert not validate_station_name(name).ok, name


def test_valid_ip_suite():
    assert validate_ip_suite("192.168.1.10", "255.255.255.0", "192.168.1.1").ok
    assert validate_ip_suite("10.0.0.2", "255.0.0.0", "0.0.0.0").ok


def test_invalid_ip_suites():
    assert not validate_ip_suite("192.168.1.255", "255.255.255.0", "192.168.1.1").ok
    assert not validate_ip_suite("192.168.1.10", "255.255.255.0", "10.0.0.1").ok
    assert not validate_ip_suite("127.0.0.1", "255.0.0.0", "0.0.0.0").ok
    assert not validate_ip_suite("224.0.0.1", "255.255.255.0", "0.0.0.0").ok
    assert not validate_ip_suite("192.168.1.10", "255.0.255.0", "0.0.0.0").ok
    assert not validate_ip_suite("0.0.0.0", "255.255.255.0", "0.0.0.0").ok


def test_mask_and_mac_and_vlan():
    assert validate_netmask("255.255.255.0").ok
    assert not validate_netmask("255.0.255.0").ok
    assert validate_mac("02:00:00:00:00:11").ok
    assert validate_mac("02-00-00-00-00-11").ok
    assert not validate_mac("02:00:00:00:11").ok
    assert validate_vlan(None).ok
    assert validate_vlan(1).ok
    assert not validate_vlan(0).ok
    assert not validate_vlan(4095).ok


def test_response_delay_factor():
    assert validate_response_delay_factor(1).ok
    assert validate_response_delay_factor(6400).ok
    assert not validate_response_delay_factor(0).ok
    assert not validate_response_delay_factor(6401).ok
    assert validate_response_delay_factor(600).warnings
