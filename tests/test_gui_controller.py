"""Tests for the session controller — no ``QWidget`` is constructed."""

from __future__ import annotations

import pytest

from dcpstudio.gui.controller import SessionController, SessionNotReady
from dcpstudio.mock import MockNetwork, MockTransport, default_mock_devices
from dcpstudio.operations import confirmation_for, set_name_spec
from dcpstudio.services.capture import FrameRouter
from dcpstudio.services.discovery import DiscoveryConfig
from dcpstudio.services.write import (
    WriteAuthorization,
    WriteConfig,
    WriteRequest,
    identity_text,
)
from dcpstudio.transport.interfaces import MOCK_INTERFACE

TARGET = "02:00:00:00:00:11"


def _controller() -> SessionController:
    controller = SessionController()
    transport = MockTransport(
        MockNetwork(default_mock_devices()), interface=MOCK_INTERFACE
    )
    controller.current_interface = MOCK_INTERFACE
    controller.open_interface(
        router=FrameRouter(),
        min_interval_s=0.0,
        event_log=None,
        transport=transport,
        register_listeners=True,
    )
    transport.start_capture()
    return controller


def test_operations_are_refused_before_an_interface_is_active():
    controller = SessionController()

    with pytest.raises(SessionNotReady):
        controller.discover(DiscoveryConfig())


def test_controller_discovers_without_a_window():
    controller = _controller()
    try:
        result = controller.discover(DiscoveryConfig(timeout_s=0.5))
    finally:
        controller.close()

    assert result.devices
    assert controller.discovery_service is not None
    assert controller.last_readiness is not None


def test_controller_ingests_devices_into_its_cache():
    controller = _controller()
    try:
        result = controller.discover(DiscoveryConfig(timeout_s=0.5))
        controller.ingest_devices(result.devices)
        controller.ingest_devices(result.devices)  # idempotent merge
    finally:
        controller.close()

    assert len(controller.device_cache) == len(result.devices)
    assert all(key[0] == MOCK_INTERFACE.id for key in controller.device_cache)


def test_controller_executes_a_guarded_write_without_a_window():
    controller = _controller()
    controller.safety_gate.enable_configuration_mode(explicit_authorization=True)
    try:
        discovered = controller.discover(DiscoveryConfig(timeout_s=0.5))
        device = next(d for d in discovered.devices if d.mac.lower() == TARGET)
        spec = set_name_spec("line-99.tested", permanent=False)
        confirmation = confirmation_for(
            spec,
            interface_id=MOCK_INTERFACE.id,
            interface_name=MOCK_INTERFACE.name,
            target_mac=TARGET,
            target_identity=identity_text(device),
        )
        request = WriteRequest(
            kind="set_name",
            target_mac=TARGET,
            confirmation=confirmation,
            authorization=WriteAuthorization(
                authorization_confirmed=True, safe_maintenance_confirmed=True
            ),
            config=WriteConfig(timeout_s=0.5, min_request_interval_s=0.0),
            name="line-99.tested",
            permanent=False,
        )
        result = controller.execute_write(request)
    finally:
        controller.close()

    assert result.state == "acknowledged"
    assert result.verification == "verified"


def test_reset_session_forgets_state_and_disarms_the_safety_gate():
    controller = _controller()
    controller.safety_gate.enable_configuration_mode(explicit_authorization=True)
    result = controller.discover(DiscoveryConfig(timeout_s=0.5))
    controller.ingest_devices(result.devices)
    controller.selected_device = result.devices[0]

    controller.reset_session()

    assert controller.transport is None
    assert controller.discovery_service is None
    assert controller.get_service is None
    assert controller.write_service is None
    assert controller.signal_service is None
    assert controller.current_interface is None
    assert controller.device_cache == {}
    assert controller.selected_device is None
    assert controller.discovery_runs == []
    assert controller.transactions == []
    assert controller.safety_gate.configuration_mode is False
