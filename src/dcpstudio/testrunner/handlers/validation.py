"""Handlers for the ``validation.*`` functional-test namespace."""

from __future__ import annotations

from ...model import TestResult
from ...validation import validate_ip_suite, validate_station_name


class ValidationHandlersMixin:
    def _test_validation_station_name(self, case, cancel_event) -> TestResult:
        valid = ["line-01.conveyor", "a", "", "port-1.device"]
        invalid = ["Line-01", "-device", "device-", "a..b", "192.168.1.10", "port-001"]
        failures = []
        for name in valid:
            report = validate_station_name(name)
            if not report.ok:
                failures.append(f"valid name rejected: {name!r} ({report.summary()})")
        for name in invalid:
            report = validate_station_name(name)
            if report.ok:
                failures.append(f"invalid name accepted: {name!r}")
        if failures:
            return self._result(case, "failed", "; ".join(failures))
        return self._result(
            case,
            "passed",
            "Station-name validation matches the documented PROFINET rules",
            evidence={"valid": valid, "invalid": invalid},
        )

    def _test_validation_ip_suite(self, case, cancel_event) -> TestResult:
        checks = {
            "valid": validate_ip_suite("192.168.1.10", "255.255.255.0", "192.168.1.1").ok,
            "gateway_off_subnet": not validate_ip_suite(
                "192.168.1.10", "255.255.255.0", "10.0.0.1"
            ).ok,
            "broadcast": not validate_ip_suite(
                "192.168.1.255", "255.255.255.0", "192.168.1.1"
            ).ok,
            "loopback": not validate_ip_suite("127.0.0.1", "255.0.0.0", "0.0.0.0").ok,
            "non_contiguous_mask": not validate_ip_suite(
                "192.168.1.10", "255.0.255.0", "192.168.1.1"
            ).ok,
        }
        if all(checks.values()):
            return self._result(
                case, "passed", "IPv4 suite validation behaves as documented", evidence=checks
            )
        return self._result(
            case,
            "failed",
            "IPv4 validation mismatch: " + ", ".join(k for k, v in checks.items() if not v),
            evidence=checks,
        )
