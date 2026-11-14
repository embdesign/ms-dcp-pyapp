from __future__ import annotations

import pytest

from dcpstudio.safety import ConfirmationRequest, SafetyError, SafetyGate


def _request(destructiveness: str = "state-changing") -> ConfirmationRequest:
    return ConfirmationRequest(
        operation_id="test",
        operation_text="Set NameOfStation",
        interface_id="eth0",
        target_mac="02:00:00:00:00:11",
        target_identity="line-01.conveyor",
        proposed_parameters={"name": "line-02.conveyor"},
        consequences=["May interrupt communication"],
        destructiveness=destructiveness,
    )


def test_configuration_mode_is_off_by_default():
    gate = SafetyGate()
    assert gate.configuration_mode is False
    with pytest.raises(SafetyError):
        gate.require_configuration_mode("Set NameOfStation")


def test_configuration_mode_requires_explicit_authorization():
    gate = SafetyGate()
    with pytest.raises(SafetyError):
        gate.enable_configuration_mode(explicit_authorization=False)
    gate.enable_configuration_mode(explicit_authorization=True)
    assert gate.configuration_mode is True
    gate.disable_configuration_mode()
    assert gate.configuration_mode is False


def test_confirmation_requires_authorization_and_safe_state():
    gate = SafetyGate()
    gate.enable_configuration_mode(explicit_authorization=True)
    request = _request()
    with pytest.raises(SafetyError):
        gate.confirm(request, safe_maintenance_confirmed=True)
    with pytest.raises(SafetyError):
        gate.confirm(
            request,
            authorization_confirmed=True,
            safe_maintenance_confirmed=False,
        )
    assert (
        gate.confirm(
            request,
            authorization_confirmed=True,
            safe_maintenance_confirmed=True,
        )
        is True
    )


def test_factory_reset_uses_the_same_two_checks():
    gate = SafetyGate()
    gate.enable_configuration_mode(explicit_authorization=True)
    request = _request("factory-reset")
    with pytest.raises(SafetyError):
        gate.confirm(request, safe_maintenance_confirmed=True)
    assert gate.confirm(
        request,
        authorization_confirmed=True,
        safe_maintenance_confirmed=True,
    )


def test_batch_and_broadcast_are_rejected():
    gate = SafetyGate()
    gate.enable_configuration_mode(explicit_authorization=True)
    request = _request()
    request.allows_batch = True
    with pytest.raises(SafetyError):
        gate.confirm(
            request,
            authorization_confirmed=True,
            safe_maintenance_confirmed=True,
        )


def test_target_revalidation():
    gate = SafetyGate()
    request = _request()
    gate.revalidate_target(request, live_mac="02:00:00:00:00:11", live_identity="line-01.conveyor")
    with pytest.raises(SafetyError):
        gate.revalidate_target(request, live_mac="02:00:00:00:00:12", live_identity=None)
    with pytest.raises(SafetyError):
        gate.revalidate_target(
            request, live_mac="02:00:00:00:00:11", live_identity="different"
        )

