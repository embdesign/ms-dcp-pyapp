"""Validation helpers for PROFINET names and IPv4 parameters.

These rules mirror the checks in p-net's ``pf_cmina.c`` (PROFINET 2.4
§4.3.1.4.16.2 and §4.3.1.4.21). They are used by the guarded configuration form,
the Set builders and tests.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from .constants import FULL_IP_SUITE_DNS_SERVERS

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
_STATION_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
_PORT_LABEL_RE = re.compile(r"^port-[0-9]{3}(-[0-9]{5})?$")
_STATION_MAX = 240


@dataclass(slots=True)
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def add_error(self, text: str) -> None:
        self.errors.append(text)

    def add_warning(self, text: str) -> None:
        self.warnings.append(text)

    def summary(self) -> str:
        if self.ok and not self.warnings:
            return "Valid"
        parts: list[str] = []
        if self.errors:
            parts.append("Invalid: " + "; ".join(self.errors))
        if self.warnings:
            parts.append("Warnings: " + "; ".join(self.warnings))
        return " | ".join(parts)


def validate_mac(value: str) -> ValidationReport:
    report = ValidationReport()
    if not _MAC_RE.match(value.strip()):
        report.add_error("MAC address must have six hexadecimal octets")
    return report


def validate_vlan(value: int | None) -> ValidationReport:
    report = ValidationReport()
    if value is not None and not 1 <= int(value) <= 4094:
        report.add_error("VLAN ID must be 1..4094 (or empty for untagged)")
    return report


def validate_station_name(value: str) -> ValidationReport:
    """Validate a PROFINET NameOfStation.

    An empty string is valid and means "no station name set" (p-net accepts it
    for this reason). Labels are lowercase; uppercase is rejected rather than
    silently converted.
    """
    report = ValidationReport()
    if value == "":
        return report
    if len(value) > _STATION_MAX:
        report.add_error(f"Station name exceeds {_STATION_MAX} characters")
        return report
    if value.startswith("-"):
        report.add_error("Station name must not start with '-'")
    if value.endswith("-"):
        report.add_error("Station name must not end with '-'")
    labels = value.split(".")
    for label in labels:
        if not label:
            report.add_error("Station name contains an empty label")
            continue
        if len(label) > 63:
            report.add_error(f"Label {label!r} exceeds 63 characters")
        if not _STATION_LABEL_RE.match(label):
            report.add_error(
                f"Label {label!r} may contain only lowercase a-z, digits and '-'"
            )
        if label.startswith("-") or label.endswith("-"):
            report.add_error(f"Label {label!r} must not start or end with '-'")
    if _PORT_LABEL_RE.match(labels[0]):
        report.add_error(
            "The first label must not have the reserved form 'port-xyz' or "
            "'port-xyz-abcde'"
        )
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        report.add_error("Station name must not look like an IPv4 address (a.b.c.d)")
    return report


def _ipv4_int(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


def validate_netmask(value: str) -> ValidationReport:
    report = ValidationReport()
    try:
        mask = _ipv4_int(value)
    except ValueError:
        report.add_error("Subnet mask is not a valid IPv4 address")
        return report
    if mask == 0:
        report.add_warning("A zero subnet mask is only meaningful with an unset IP")
        return report
    # A valid contiguous mask has the form 1..10..0.
    inverted = (~mask) & 0xFFFFFFFF
    if inverted & (inverted + 1):
        report.add_error("Subnet mask is not contiguous")
    return report


def validate_ip_suite(ip: str, mask: str, gateway: str) -> ValidationReport:
    """Validate an IPv4 address, mask and gateway as one consistent suite."""
    report = ValidationReport()
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        mask_obj = ipaddress.IPv4Address(mask)
        gw_obj = ipaddress.IPv4Address(gateway) if gateway else ipaddress.IPv4Address("0.0.0.0")
    except ValueError as exc:
        report.add_error(f"Invalid IPv4 value: {exc}")
        return report

    report.errors.extend(validate_netmask(mask).errors)
    report.warnings.extend(validate_netmask(mask).warnings)
    if report.errors:
        return report

    mask_int = int(mask_obj)
    ip_int = int(ip_obj)
    if ip_int == 0:
        report.add_error("IP address must not be 0.0.0.0 for a configuration")
        return report
    if ip_int <= int(ipaddress.IPv4Address("0.255.255.255")):
        report.add_error("IP address is in a reserved range")
    if int(ipaddress.IPv4Address("127.0.0.0")) <= ip_int <= int(
        ipaddress.IPv4Address("127.255.255.255")
    ):
        report.add_error("Loopback addresses cannot be assigned to a PROFINET device")
    if int(ipaddress.IPv4Address("224.0.0.0")) <= ip_int <= int(
        ipaddress.IPv4Address("239.255.255.255")
    ):
        report.add_error("Multicast addresses cannot be assigned")
    if ip_int >= int(ipaddress.IPv4Address("240.0.0.0")):
        report.add_error("Reserved class E addresses cannot be assigned")

    host_part = ip_int & ~mask_int
    if mask_int and host_part in (0, (~mask_int) & 0xFFFFFFFF):
        report.add_error("IP address must not be the network or broadcast address")

    if gateway and int(gw_obj) != 0:
        if (ip_int & mask_int) != (int(gw_obj) & mask_int):
            report.add_error("Gateway is not in the same subnet as the IP address")
    return report


def validate_dns_servers(values: Sequence[str]) -> ValidationReport:
    """Validate the DNS server list of a Full IP suite (01/03).

    The wire format has exactly four IPv4 slots (Wireshark pn_dcp). An empty
    value or ``0.0.0.0`` means "no DNS server"; other addresses must be plain
    IPv4 literals.
    """
    report = ValidationReport()
    entries = [value.strip() for value in values if value.strip()]
    if len(entries) > FULL_IP_SUITE_DNS_SERVERS:
        report.add_error(
            f"At most {FULL_IP_SUITE_DNS_SERVERS} DNS servers are supported"
        )
    seen: set[str] = set()
    for entry in entries:
        try:
            address = ipaddress.IPv4Address(entry)
        except ValueError:
            report.add_error(f"Invalid DNS server address {entry!r}")
            continue
        if int(address) == 0:
            continue
        key = str(address)
        if key in seen:
            report.add_warning(f"DNS server {key} is listed more than once")
        seen.add(key)
        if int(address) >= int(ipaddress.IPv4Address("224.0.0.0")):
            report.add_error(f"DNS server {key} must be a unicast IPv4 address")
    return report


def validate_discovery_timeout(value: float) -> ValidationReport:
    report = ValidationReport()
    if not 0.5 <= float(value) <= 60.0:
        report.add_error("Discovery timeout must be 0.5..60 seconds")
    return report


def validate_response_delay_factor(value: int) -> ValidationReport:
    report = ValidationReport()
    if not 1 <= int(value) <= 6400:
        report.add_error("ResponseDelayFactor must be 1..6400 (units of 10 ms)")
    elif int(value) > 500:
        report.add_warning(
            "A large ResponseDelayFactor can spread replies over many seconds; "
            "increase the discovery timeout accordingly"
        )
    return report
