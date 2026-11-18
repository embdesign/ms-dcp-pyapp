"""Handlers for the ``env.*`` functional-test namespace."""

from __future__ import annotations

from ...model import TestResult


class EnvHandlersMixin:
    def _test_env_interface(self, case, cancel_event) -> TestResult:
        iface = self.transport.interface
        evidence = {
            "name": iface.name,
            "id": iface.id,
            "mac": iface.mac,
            "link": iface.link_text,
            "kind": iface.kind,
        }
        if not iface.mac:
            return self._result(case, "failed", "Interface has no MAC address", evidence=evidence)
        if iface.is_loopback:
            return self._result(
                case,
                "inconclusive",
                "Loopback interface cannot reach a physical PROFINET segment",
                evidence=evidence,
            )
        if iface.is_up is False:
            return self._result(
                case, "inconclusive", "Interface link is down", evidence=evidence
            )
        return self._result(
            case, "passed", f"Interface {iface.name} ({iface.mac}) is usable", evidence=evidence
        )

    def _test_env_readiness(self, case, cancel_event) -> TestResult:
        readiness = self.transport.readiness()
        evidence = readiness.to_dict()
        if readiness.ready:
            return self._result(case, "passed", readiness.message, evidence=evidence)
        return self._result(
            case,
            "failed",
            readiness.message,
            evidence=evidence,
            warnings=readiness.hints,
        )

    def _test_env_capture(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        if not self.transport.is_capturing:
            return self._result(case, "failed", "Capture did not enter the running state")
        return self._result(
            case,
            "passed",
            f"{message}; passive capture is running on {self.transport.interface.name}",
            evidence={"interface": self.transport.interface.id},
        )
