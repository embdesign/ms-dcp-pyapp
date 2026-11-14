from __future__ import annotations

from dcpstudio.config import AppConfig
from dcpstudio.logging_setup import EventLogger
from dcpstudio.mock import MockNetwork, MockTransport, default_mock_devices
from dcpstudio.model import DeviceIdentity, utc_now
from dcpstudio.safety import SafetyGate
from dcpstudio.services.write import WriteAuthorization
from dcpstudio.testrunner.runner import TEST_CASES, TestRunner
from dcpstudio.transport.interfaces import MOCK_INTERFACE


def _runner(timeout_s: float = 0.5) -> tuple[TestRunner, MockTransport]:
    transport = MockTransport(MockNetwork())
    runner = TestRunner(
        transport,
        AppConfig(timeout_s=timeout_s, min_request_interval_s=0.1),
        event_log=EventLogger(),
    )
    return runner, transport


def test_offline_tests_pass():
    runner, transport = _runner()
    try:
        results = runner.run(
            {
                "parser.fixture_decode",
                "parser.malformed",
                "parser.pcap_roundtrip",
                "parser.block_errors",
                "protocol.transaction_matching",
                "protocol.get_offline",
                "validation.station_name",
                "validation.ip_suite",
            }
        )
    finally:
        transport.close()
    assert len(results) == 8
    assert all(result.status == "passed" for result in results), [
        (r.test_id, r.status, r.detail) for r in results
    ]


def test_mock_live_tests_pass():
    runner, transport = _runner()
    try:
        results = runner.run(
            {
                "env.readiness",
                "protocol.identify_discovery",
                "protocol.get_live",
                "protocol.unicast_identify",
                "protocol.identity_before_after",
                "protocol.response_times",
            }
        )
    finally:
        transport.close()
    assert all(result.status == "passed" for result in results), [
        (r.test_id, r.status, r.detail) for r in results
    ]


def test_repeat_discovery_is_bounded_and_paced():
    runner, transport = _runner()
    try:
        result = runner.run({"protocol.repeat_discovery"})[0]
    finally:
        transport.close()
    assert result.status == "passed"
    assert len(result.evidence["rounds"]) == 3
    assert all(round_["devices"] for round_ in result.evidence["rounds"])


def test_guarded_write_tests_are_skipped_without_authorization():
    runner, transport = _runner()
    try:
        results = runner.run({"write.set_name", "write.set_ip", "write.reset"})
    finally:
        transport.close()
    assert [r.status for r in results] == ["skipped", "skipped", "skipped"]
    assert any("No target" in r.detail or "No " in r.detail for r in results)


def _target(device) -> DeviceIdentity:
    now = utc_now()
    return DeviceIdentity(
        interface_id=MOCK_INTERFACE.id,
        mac=device.mac,
        first_seen=now,
        last_seen=now,
        name_of_station=device.name,
        ip_address=device.ip,
        subnet_mask=device.mask,
        gateway=device.gateway,
        vendor_id=device.vendor_id,
        device_id=device.device_id,
        vendor_name=device.vendor_name,
        device_role_flags=device.role_flags,
    )


def test_guarded_set_name_runs_with_confirmation():
    device = default_mock_devices()[0]
    transport = MockTransport(MockNetwork([device]))
    gate = SafetyGate()
    gate.enable_configuration_mode(explicit_authorization=True)
    runner = TestRunner(
        transport,
        AppConfig(timeout_s=0.5, min_request_interval_s=0.05),
        event_log=EventLogger(),
        safety_gate=gate,
        target=_target(device),
        write_authorizations={
            "write.set_name": WriteAuthorization(
                authorization_confirmed=True,
                safe_maintenance_confirmed=True,
            )
        },
        write_parameters={
            "write.set_name": {"name": "line-99.tested", "permanent": False}
        },
    )
    try:
        result = runner.run({"write.set_name"})[0]
    finally:
        transport.close()
    assert result.status == "passed", result.detail
    assert result.evidence["write"]["verification"] == "verified"
    assert device.name == "line-99.tested"


def test_guarded_reset_is_inconclusive_and_gets_post_checked():
    device = default_mock_devices()[0]
    target = _target(device)
    transport = MockTransport(MockNetwork([device]))
    gate = SafetyGate()
    gate.enable_configuration_mode(explicit_authorization=True)
    runner = TestRunner(
        transport,
        AppConfig(timeout_s=0.5, min_request_interval_s=0.05),
        event_log=EventLogger(),
        safety_gate=gate,
        target=target,
        write_authorizations={
            "write.reset": WriteAuthorization(
                authorization_confirmed=True,
                safe_maintenance_confirmed=True,
            )
        },
        write_parameters={"write.reset": {"reset_mode": 8}},
    )
    try:
        result = runner.run({"write.reset"})[0]
    finally:
        transport.close()
    assert result.status == "inconclusive"
    assert result.evidence["write"]["state"] == "acknowledged"
    assert result.evidence["write"]["post_check_state"] == "responded"
    assert device.name == ""
    assert device.ip == "0.0.0.0"


def test_all_declared_test_ids_have_handlers():
    handler_names = {
        f"_test_{case.test_id.replace('.', '_')}"
        for case in TEST_CASES
        if case.implemented
    }
    for name in handler_names:
        assert hasattr(TestRunner, name), name
