"""Tests for the single composition root (``dcpstudio.session``)."""

from __future__ import annotations

from dcpstudio.mock import MockNetwork, MockTransport
from dcpstudio.services.capture import FrameRouter
from dcpstudio.session import build_services, open_session, probe_readiness
from dcpstudio.transport.interfaces import MOCK_INTERFACE


def _transport() -> MockTransport:
    return MockTransport(MockNetwork(), interface=MOCK_INTERFACE)


def test_build_services_registers_every_service_on_the_router():
    transport = _transport()
    router = FrameRouter()
    registered: list = []
    router.add_listener = registered.append  # type: ignore[method-assign]

    services = build_services(MOCK_INTERFACE, transport=transport, router=router)

    assert services.transport is transport
    assert services.router is router
    assert services.interface is MOCK_INTERFACE
    assert services.signal is not None
    assert [listener.__self__ for listener in registered] == [
        services.discovery,
        services.getter,
        services.writer,
        services.signal,
    ]


def test_build_services_can_omit_signal():
    services = build_services(
        MOCK_INTERFACE,
        transport=_transport(),
        include_signal=False,
    )
    assert services.signal is None


def test_build_services_shares_one_rate_limiter():
    services = build_services(MOCK_INTERFACE, transport=_transport())

    assert services.discovery.limiter is services.limiter
    assert services.getter.limiter is services.limiter
    assert services.writer.limiter is services.limiter
    assert services.signal is not None
    assert services.signal.limiter is services.limiter


def test_build_services_reuses_the_injected_safety_gate():
    from dcpstudio.safety import SafetyGate

    gate = SafetyGate()
    services = build_services(MOCK_INTERFACE, transport=_transport(), safety=gate)

    assert services.safety is gate
    assert services.writer.safety is gate


def test_open_session_starts_and_stops_capture():
    with open_session(MOCK_INTERFACE) as session:
        assert session.transport.is_capturing
    assert not session.transport.is_capturing


def test_probe_readiness_builds_a_transport():
    readiness = probe_readiness(MOCK_INTERFACE)
    assert readiness.ready is True
    assert readiness.platform == "mock"
