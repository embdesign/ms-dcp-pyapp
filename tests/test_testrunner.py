from __future__ import annotations

from dcpstudio.config import AppConfig
from dcpstudio.logging_setup import EventLogger
from dcpstudio.mock import MockNetwork, MockTransport, default_mock_devices
from dcpstudio.model import DeviceIdentity, utc_now
from dcpstudio.safety import SafetyGate
from dcpstudio.services.write import WriteAuthorization
from dcpstudio.testrunner.cases import (
    DEVICE_READ_ONLY_SUITE,
    DEVICE_VALIDATION_SUITE,
    FULL_VALIDATION_SUITE,
    TEST_GROUPS,
    TEST_SUITES,
    TOOL_SELF_TEST_SUITE,
    cases_by_id,
    default_test_ids,
    grouped_cases,
    suite_test_ids,
)
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


def test_categories_match_the_declared_groups():
    declared = [name for name, _ in TEST_GROUPS]
    grouped = grouped_cases()
    assert [name for name, _, _ in grouped] == declared
    assert sum(len(cases) for _, _, cases in grouped) == len(TEST_CASES)
    # Every case carries the note of exactly one declared group.
    assert {case.category for case in TEST_CASES} == set(declared)
    for name, note, cases in grouped:
        assert note
        assert all(case.category == name for case in cases)


def test_suites_are_implemented_subsets():
    by_id = cases_by_id()
    for suite in TEST_SUITES:
        assert suite.title and suite.description
        assert len(set(suite.test_ids)) == len(suite.test_ids), suite.key
        for test_id in suite.test_ids:
            case = by_id[test_id]
            assert case.implemented, f"{suite.key}: {test_id} is not implemented"
        assert set(suite_test_ids(suite)) == set(suite.test_ids)


def test_only_the_validation_suites_write():
    for suite in (TOOL_SELF_TEST_SUITE, DEVICE_READ_ONLY_SUITE):
        assert not suite.sends_writes
        assert suite.write_test_ids == ()
        assert set(suite.test_ids) <= set(default_test_ids())
    for suite in (DEVICE_VALIDATION_SUITE, FULL_VALIDATION_SUITE):
        assert suite.sends_writes
        assert suite.write_test_ids == (
            "write.set_name",
            "write.set_ip",
            "write.reset",
        )


def test_read_only_suites_cover_exactly_the_default_catalogue():
    assert set(TOOL_SELF_TEST_SUITE.test_ids) | set(
        DEVICE_READ_ONLY_SUITE.test_ids
    ) == set(default_test_ids())


def test_device_validation_adds_the_writes_after_the_read_checks():
    assert set(DEVICE_VALIDATION_SUITE.test_ids) == set(
        DEVICE_READ_ONLY_SUITE.test_ids
    ) | set(DEVICE_VALIDATION_SUITE.write_test_ids)
    # Read checks first; the reset (which may revert name/IP) is last.
    assert DEVICE_VALIDATION_SUITE.test_ids[: len(DEVICE_READ_ONLY_SUITE.test_ids)] == (
        DEVICE_READ_ONLY_SUITE.test_ids
    )
    assert DEVICE_VALIDATION_SUITE.test_ids[-1] == "write.reset"
    assert set(FULL_VALIDATION_SUITE.test_ids) == set(
        TOOL_SELF_TEST_SUITE.test_ids
    ) | set(DEVICE_VALIDATION_SUITE.test_ids)


def test_device_read_only_suite_passes_against_the_mock_network():
    runner, transport = _runner()
    try:
        results = runner.run(set(DEVICE_READ_ONLY_SUITE.test_ids))
    finally:
        transport.close()
    assert {result.test_id for result in results} == set(
        DEVICE_READ_ONLY_SUITE.test_ids
    )
    assert all(result.status == "passed" for result in results), [
        (result.test_id, result.status, result.detail) for result in results
    ]
    # The environment checks run before the live checks in catalogue order.
    assert results[0].test_id.startswith("env.")


def test_device_validation_suite_reads_and_writes_against_the_mock_network():
    device = default_mock_devices()[0]
    transport = MockTransport(MockNetwork([device]))
    gate = SafetyGate()
    gate.enable_configuration_mode(explicit_authorization=True)
    authorization = WriteAuthorization(
        authorization_confirmed=True,
        safe_maintenance_confirmed=True,
    )
    runner = TestRunner(
        transport,
        AppConfig(timeout_s=0.5, min_request_interval_s=0.05),
        event_log=EventLogger(),
        safety_gate=gate,
        target=_target(device),
        write_authorizations={
            test_id: authorization
            for test_id in DEVICE_VALIDATION_SUITE.write_test_ids
        },
        write_parameters={
            "write.set_name": {"name": "line-99.validated", "permanent": False},
            "write.set_ip": {
                "ip_address": "192.0.2.99",
                "subnet_mask": "255.255.255.0",
                "gateway": "192.0.2.1",
                "permanent": False,
            },
            "write.reset": {"reset_mode": 8},
        },
    )
    try:
        results = runner.run(set(DEVICE_VALIDATION_SUITE.test_ids))
    finally:
        transport.close()
    by_id = {result.test_id: result for result in results}
    assert by_id["write.set_name"].status == "passed"
    assert by_id["write.set_ip"].status == "passed"
    # An acknowledged reset is an unknown outcome, never "passed".
    assert by_id["write.reset"].status == "inconclusive"
    assert all(
        result.status == "passed"
        for result in results
        if not result.test_id.startswith("write.")
    ), [(r.test_id, r.status, r.detail) for r in results]
    assert device.name == "" and device.ip == "0.0.0.0"


def test_identity_completeness_reports_missing_name_as_a_warning():
    runner, transport = _runner()
    try:
        result = runner.run({"protocol.identity_completeness"})[0]
    finally:
        transport.close()
    assert result.status == "passed", result.detail
    assert any("NameOfStation" in warning for warning in result.warnings)
