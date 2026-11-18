"""Functional test runner: read-only checks plus optional guarded writes.

Read-only tests never change equipment. Optional Name/IP Set and Reset tests
require configuration mode, a selected target, and a separate per-operation
confirmation
supplied before the run. No fuzzing is sent to live equipment, no continuous
scanning is performed, and every state-changing request is single-shot.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from ..config import AppConfig
from ..logging_setup import EventLogger
from ..model import DeviceIdentity, TestResult, utc_now
from ..safety import SafetyGate
from ..services.discovery import DiscoveryService
from ..services.get import GetService
from ..services.write import (
    WriteAuthorization,
    WriteService,
)
from ..session import build_services
from ..transport.base import DcpTransport
from .cases import TEST_CASES, TestCase
from .handlers import (
    EnvHandlersMixin,
    ParserHandlersMixin,
    ProtocolHandlersMixin,
    ValidationHandlersMixin,
    WriteHandlersMixin,
)

ProgressCallback = Callable[[int, int, str], None]


class TestRunner(
    EnvHandlersMixin,
    ParserHandlersMixin,
    ProtocolHandlersMixin,
    ValidationHandlersMixin,
    WriteHandlersMixin,
):
    __test__ = False

    def __init__(
        self,
        transport: DcpTransport,
        config: AppConfig,
        *,
        event_log: EventLogger | None = None,
        discovery_service: DiscoveryService | None = None,
        get_service: GetService | None = None,
        write_service: WriteService | None = None,
        safety_gate: SafetyGate | None = None,
        target: DeviceIdentity | None = None,
        write_authorizations: dict[str, WriteAuthorization] | None = None,
        write_parameters: dict[str, dict] | None = None,
    ) -> None:
        self.transport = transport
        self.config = config
        self.event_log = event_log
        self.discovery_service = discovery_service
        self.get_service = get_service
        self.write_service = write_service
        self.safety_gate = safety_gate or SafetyGate()
        self.target = target
        self.write_authorizations = dict(write_authorizations or {})
        self.write_parameters = dict(write_parameters or {})
        self.latest_discovery = None
        self._callback_installed = (
            discovery_service is not None
            and get_service is not None
            and write_service is not None
        )

    def _ensure_services(self) -> tuple[DiscoveryService, GetService, WriteService]:
        """Build the service graph once, through the shared composition root.

        A caller may instead inject all three services (the CLI and the GUI do,
        because they already own a router and callback); in that case the
        caller also owns the frame callback, exactly as before.
        """

        def event_log(event: str, message: str, detail: dict) -> None:
            if self.event_log:
                self.event_log.info(event, message, detail)

        injected = (self.discovery_service, self.get_service, self.write_service)
        if all(item is None for item in injected):
            services = build_services(
                self.transport.interface,
                safety=self.safety_gate,
                event_log=event_log,
                transport=self.transport,
            )
            self.discovery_service = services.discovery
            self.get_service = services.getter
            self.write_service = services.writer
            self._callback_installed = True
        elif not all(item is not None for item in injected):
            raise ValueError(
                "TestRunner needs either no services (it builds them) or all of "
                "discovery, Get and Write."
            )
        return self.discovery_service, self.get_service, self.write_service

    def _discovery(self) -> DiscoveryService:
        return self._ensure_services()[0]

    def _getter(self) -> GetService:
        return self._ensure_services()[1]

    def _writer(self) -> WriteService:
        return self._ensure_services()[2]

    def list_tests(self) -> list[TestCase]:
        return list(TEST_CASES)

    def run(
        self,
        selected_ids: set[str] | None = None,
        *,
        cancel_event: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> list[TestResult]:
        cancel_event = cancel_event or threading.Event()
        cases = [
            case
            for case in TEST_CASES
            if selected_ids is None or case.test_id in selected_ids
        ]
        results: list[TestResult] = []
        total = len(cases)
        for index, case in enumerate(cases, start=1):
            if progress:
                progress(index, total, case.name)
            if cancel_event.is_set():
                break
            results.append(self._execute(case, cancel_event))
        return results

    def _execute(self, case: TestCase, cancel_event: threading.Event) -> TestResult:
        started = utc_now()
        t0 = time.monotonic()
        try:
            if not case.implemented:
                result = TestResult(
                    test_id=case.test_id,
                    name=case.name,
                    category=case.category,
                    status="skipped",
                    detail=(
                        "Not implemented in this build. Disabled by design; it "
                        "cannot be selected and no DCP request is transmitted."
                    ),
                    started_at=started,
                    duration_ms=0.0,
                    live=case.live,
                )
            else:
                handler = getattr(self, f"_test_{case.test_id.replace('.', '_')}")
                result = handler(case, cancel_event)
        except Exception as exc:
            result = TestResult(
                test_id=case.test_id,
                name=case.name,
                category=case.category,
                status="failed",
                detail=f"Test raised {type(exc).__name__}: {exc}",
                started_at=started,
                duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
                live=case.live,
            )
        result.duration_ms = round((time.monotonic() - t0) * 1000.0, 3)
        if self.event_log:
            self.event_log.log(
                "INFO" if result.status == "passed" else "WARNING",
                "test.result",
                f"{case.test_id}: {result.status}",
                result.to_dict(),
            )
        return result

    # ------------------------------------------------------------------ tests
    def _result(
        self,
        case: TestCase,
        status: str,
        detail: str,
        *,
        started=None,
        evidence: dict | None = None,
        warnings: list[str] | None = None,
    ) -> TestResult:
        return TestResult(
            test_id=case.test_id,
            name=case.name,
            category=case.category,
            status=status,
            detail=detail,
            started_at=started or utc_now(),
            duration_ms=0.0,
            live=case.live,
            evidence=evidence or {},
            warnings=warnings or [],
        )

    def _ensure_capture(self) -> tuple[bool, str]:
        if self.transport.is_capturing:
            return True, "Capture already running"
        try:
            self.transport.start_capture()
            return True, "Capture started"
        except Exception as exc:
            return False, str(exc)

    def _preferred_target(self) -> DeviceIdentity | None:
        """The operator-selected device, else the first device of the last discovery.

        Read-only tests prefer an explicit selection so a suite run validates the
        device the operator picked instead of whichever responder was fastest.
        """
        if self.target is not None:
            return self.target
        if self.latest_discovery is not None and self.latest_discovery.devices:
            return self.latest_discovery.devices[0]
        return None

    # Test handlers live in ``handlers/<namespace>.py``; ``_execute`` resolves
    # them through ``getattr(self, f"_test_{id}")`` across the mixins.

