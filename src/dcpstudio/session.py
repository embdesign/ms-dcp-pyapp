"""Single composition root for the transport and the DCP service graph.

The GUI, the headless CLI and the functional test runner all need the same
wiring: one transport, one ``FrameRouter``, one shared ``RequestRateLimiter``,
and the discovery/Get/Write/Signal services listening on the same frames. Before
this module existed that wiring was repeated in three places and had already
drifted (the runner omitted ``SignalService`` and bypassed ``FrameRouter``).

Constructing the graph here keeps the adapters free of wiring knowledge and
gives the tests one place to substitute a transport. ``AGENTS.md`` records this
composition-root rule and ``tests/test_layer_boundaries.py`` enforces it.

Pure composition: this module performs no I/O itself, it only builds objects.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .constants import DEFAULT_MIN_REQUEST_INTERVAL_S
from .safety import SafetyGate
from .services.capture import FrameRouter
from .services.discovery import DiscoveryService
from .services.get import GetService
from .services.monitor import MonitorService
from .services.rate_limit import RequestRateLimiter
from .services.signal import SignalService
from .services.write import WriteService
from .transport.base import DcpTransport, FrameCallback, InterfaceInfo, Readiness
from .transport.factory import create_transport

EventLog = Callable[[str, str, dict], None]


@dataclass(slots=True)
class SessionServices:
    """The service graph for exactly one selected interface."""

    interface: InterfaceInfo
    transport: DcpTransport
    router: FrameRouter
    limiter: RequestRateLimiter
    discovery: DiscoveryService
    getter: GetService
    writer: WriteService
    signal: SignalService | None
    monitor: MonitorService
    safety: SafetyGate

    def close(self) -> None:
        """Stop capture and release the transport (safe to call twice)."""
        self.transport.close()


def build_services(
    interface: InterfaceInfo,
    *,
    min_interval_s: float = DEFAULT_MIN_REQUEST_INTERVAL_S,
    safety: SafetyGate | None = None,
    event_log: EventLog | None = None,
    router: FrameRouter | None = None,
    transport: DcpTransport | None = None,
    include_signal: bool = True,
    register_listeners: bool = True,
) -> SessionServices:
    """Build the transport and services for one interface.

    ``transport`` and ``router`` may be supplied by a caller that already owns
    them (the GUI keeps one router for the window's lifetime). With
    ``register_listeners`` the services are registered on the router and the
    router becomes the transport callback; the GUI passes ``False`` because its
    own frame handler already fans frames out.
    """
    transport = transport or create_transport(interface)
    router = router or FrameRouter()
    limiter = RequestRateLimiter(min_interval_s)
    gate = safety or SafetyGate()

    discovery = DiscoveryService(transport, limiter=limiter, event_log=event_log)
    getter = GetService(transport, limiter=limiter, event_log=event_log)
    writer = WriteService(
        transport,
        discovery_service=discovery,
        get_service=getter,
        safety=gate,
        limiter=limiter,
        event_log=event_log,
    )
    signal = (
        SignalService(transport, limiter=limiter, event_log=event_log)
        if include_signal
        else None
    )
    monitor = MonitorService(discovery, event_log=event_log)

    if register_listeners:
        listeners: list[FrameCallback] = [
            discovery.process_frame,
            getter.process_frame,
            writer.process_frame,
        ]
        if signal is not None:
            listeners.append(signal.process_frame)
        for listener in listeners:
            router.add_listener(listener)
        transport.set_frame_callback(router)

    return SessionServices(
        interface=interface,
        transport=transport,
        router=router,
        limiter=limiter,
        discovery=discovery,
        getter=getter,
        writer=writer,
        signal=signal,
        monitor=monitor,
        safety=gate,
    )


def probe_readiness(interface: InterfaceInfo) -> Readiness:
    """Build a transport just long enough to report capture readiness.

    Used for the read-only interface listing, where no service graph is needed.
    """
    transport = create_transport(interface)
    try:
        return transport.readiness()
    finally:
        transport.close()


@contextmanager
def open_session(
    interface: InterfaceInfo,
    *,
    min_interval_s: float = DEFAULT_MIN_REQUEST_INTERVAL_S,
    safety: SafetyGate | None = None,
    event_log: EventLog | None = None,
) -> Iterator[SessionServices]:
    """Build the graph, start capture, and close the transport afterwards."""
    session = build_services(
        interface,
        min_interval_s=min_interval_s,
        safety=safety,
        event_log=event_log,
    )
    session.transport.start_capture()
    try:
        yield session
    finally:
        session.close()
