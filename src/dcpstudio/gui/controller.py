"""Session state and orchestration for one selected interface.

`MainWindow` used to own both the widgets and every piece of session state:
the interface, the transport, the four services, the device cache, every result
history and the worker handles. This controller owns the **state** and the
**operations**; the window owns the widgets and the Qt slots that render the
results.

The window reaches the state through a small delegation bridge (``__getattr__``/
``__setattr__`` on a fixed attribute set), so tab mixins did not have to be
rewritten in the same step. New code should take a ``SessionController``
explicitly instead of reading window attributes.

Qt use is limited to the worker threads in ``gui/workers.py``; no widgets are
created here.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable

from ..model import (
    DeviceIdentity,
    DiscoveryResult,
    GetResult,
    TestResult,
    TransactionRecord,
    WriteResult,
)
from ..monitor import MonitorConfig, MonitorCycle, MonitorRun
from ..safety import SafetyGate
from ..services.capture import FrameRouter
from ..services.discovery import DiscoveryConfig, DiscoveryService
from ..services.get import GetConfig, GetService
from ..services.monitor import MonitorService
from ..services.rate_limit import RequestRateLimiter
from ..services.signal import SignalService
from ..services.write import WriteRequest, WriteService
from ..session import SessionServices, build_services
from ..transport.base import DcpTransport, InterfaceInfo, Readiness

ProgressCallback = Callable[[str], None]
EventLog = Callable[[str, str, dict], None]


class SessionNotReady(RuntimeError):
    """Raised when an operation is requested before an interface is active."""


class SessionController:
    """Everything about one selected interface that is not a widget."""

    def __init__(self) -> None:
        self.current_interface: InterfaceInfo | None = None
        self.transport: DcpTransport | None = None
        self.discovery_service: DiscoveryService | None = None
        self.get_service: GetService | None = None
        self.write_service: WriteService | None = None
        self.signal_service: SignalService | None = None
        self.monitor_service: MonitorService | None = None
        self.safety_gate = SafetyGate()
        self.request_limiter: RequestRateLimiter | None = None
        self.last_readiness: Readiness | None = None

        self.device_cache: dict[tuple[str, str], DeviceIdentity] = {}
        self.selected_device: DeviceIdentity | None = None

        self.latest_discovery: DiscoveryResult | None = None
        self.discovery_runs: list[DiscoveryResult] = []
        self.latest_get_result: GetResult | None = None
        self.get_runs: list[GetResult] = []
        self.latest_write_result: WriteResult | None = None
        self.latest_reset_result: WriteResult | None = None
        self.write_runs: list[WriteResult] = []
        self.transactions: list[TransactionRecord] = []
        self.latest_tests: list[TestResult] = []
        self.latest_monitor: MonitorRun | None = None
        self.monitor_runs: list[MonitorRun] = []

    # ------------------------------------------------------------ lifecycle
    def reset_session(self) -> None:
        """Close the transport and forget everything about the old interface."""
        self.close()
        self.discovery_service = None
        self.get_service = None
        self.write_service = None
        self.signal_service = None
        self.monitor_service = None
        self.request_limiter = None
        self.last_readiness = None
        self.current_interface = None

        self.device_cache.clear()
        self.selected_device = None
        self.latest_discovery = None
        self.discovery_runs.clear()
        self.latest_get_result = None
        self.get_runs.clear()
        self.latest_write_result = None
        self.latest_reset_result = None
        self.write_runs.clear()
        self.transactions.clear()
        self.latest_tests = []
        self.latest_monitor = None
        self.monitor_runs.clear()

    def open_interface(
        self,
        *,
        router: FrameRouter,
        min_interval_s: float,
        event_log: EventLog | None = None,
        transport: DcpTransport | None = None,
        register_listeners: bool = False,
    ) -> SessionServices:
        """Build the transport and services for ``current_interface``.

        ``register_listeners=False`` keeps the window's own frame fan-out in
        charge (it also feeds the capture buffer). A headless caller passes
        ``True`` so the services receive frames directly from the router.

        Raises if no interface is selected or the transport cannot be built; the
        caller keeps ownership of the error banner. On failure the controller is
        left in the reset (no transport, no services) state.
        """
        if self.current_interface is None:
            raise SessionNotReady("No interface is selected.")
        services = build_services(
            self.current_interface,
            min_interval_s=min_interval_s,
            safety=self.safety_gate,
            event_log=event_log,
            router=router,
            transport=transport,
            register_listeners=register_listeners,
        )
        self.transport = services.transport
        self.transport.set_frame_callback(router)
        self.request_limiter = services.limiter
        self.discovery_service = services.discovery
        self.get_service = services.getter
        self.write_service = services.writer
        self.signal_service = services.signal
        self.monitor_service = services.monitor
        self.last_readiness = self.transport.readiness()
        return services

    def close(self) -> None:
        transport = self.transport
        self.transport = None
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass

    # ------------------------------------------------------------ bookkeeping
    def ingest_devices(self, devices: Iterable[DeviceIdentity]) -> None:
        """Merge discovered devices into the cache, keyed by (interface, MAC)."""
        for device in devices:
            key = (device.interface_id, device.mac)
            existing = self.device_cache.get(key)
            if existing is None:
                self.device_cache[key] = device
            else:
                existing.merge(device, count_as_duplicate=False)

    # ------------------------------------------------------------ operations
    def discover(
        self,
        config: DiscoveryConfig,
        *,
        cancel_event: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> DiscoveryResult:
        if self.discovery_service is None:
            raise SessionNotReady("No interface is active.")
        return self.discovery_service.discover(
            config, cancel_event=cancel_event, progress=progress
        )

    def read_get(
        self,
        target_mac: str,
        config: GetConfig,
        *,
        cancel_event: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> GetResult:
        if self.get_service is None:
            raise SessionNotReady("No interface is active.")
        return self.get_service.get(
            target_mac, config, cancel_event=cancel_event, progress=progress
        )

    def monitor(
        self,
        config: MonitorConfig,
        *,
        cancel_event: threading.Event | None = None,
        on_cycle: Callable[[MonitorCycle], None] | None = None,
        progress: ProgressCallback | None = None,
    ) -> MonitorRun:
        if self.monitor_service is None:
            raise SessionNotReady("No interface is active.")
        run = self.monitor_service.run(
            config,
            cancel_event=cancel_event,
            on_cycle=on_cycle,
            progress=progress,
        )
        self.latest_monitor = run
        self.monitor_runs.append(run)
        if len(self.monitor_runs) > 20:
            self.monitor_runs = self.monitor_runs[-20:]
        return run

    def signal(
        self,
        target_mac: str,
        *,
        timeout_s: float,
        vlan_id: int | None,
        cancel_event: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> WriteResult:
        if self.signal_service is None:
            raise SessionNotReady("No interface is active.")
        return self.signal_service.signal(
            target_mac,
            timeout_s=timeout_s,
            vlan_id=vlan_id,
            cancel_event=cancel_event,
            progress=progress,
        )

    def execute_write(
        self,
        request: WriteRequest,
        *,
        cancel_event: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> WriteResult:
        if self.write_service is None:
            raise SessionNotReady("No interface is active.")
        return self.write_service.execute(
            request, cancel_event=cancel_event, progress=progress
        )

    def post_check(
        self,
        result: WriteResult,
        *,
        timeout_s: float,
        recheck_window_s: float = 0.0,
        cancel_event: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> WriteResult:
        if self.write_service is None:
            raise SessionNotReady("No interface is active.")
        return self.write_service.post_check(
            result,
            timeout_s=timeout_s,
            recheck_window_s=recheck_window_s,
            cancel_event=cancel_event,
            progress=progress,
        )
