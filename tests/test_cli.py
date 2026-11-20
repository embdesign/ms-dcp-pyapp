"""CLI tests against the offline demo transport.

The CLI must reuse the same services and safety gate as the GUI: read-only
commands never change equipment, a state-changing command refuses without
``--confirm``, and write test cases need ``--include-writes``.
"""

from __future__ import annotations

import json

import pytest

from dcpstudio import cli
from dcpstudio.fixtures import get_fixture
from dcpstudio.model import CapturedFrame, utc_now
from dcpstudio.pcap_io import write_pcap

DEVICE_MAC = "02:00:00:00:00:11"
FAST = (
    "-i",
    "demo0",
    "--timeout",
    "0.5",
    "--min-interval",
    "0.01",
    "--response-delay-factor",
    "1",
    "--quiet",
)
GUARDS = ("--confirm",)
FAST_SIGNAL = ("-i", "demo0", "--timeout", "0.5", "--min-interval", "0.01", "--quiet")


def _json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def test_interfaces_json_contains_demo(capsys):
    code = cli.main(["interfaces", "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert any(item["id"] == "mock:demo0" for item in output["interfaces"])
    assert "platform" in output


def test_interfaces_readiness_reports_mock(capsys):
    code = cli.main(["interfaces", "--readiness", "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    mock = next(item for item in output["interfaces"] if item["id"] == "mock:demo0")
    assert mock["readiness"]["ready"] is True


def test_discover_demo_lists_three_devices(capsys):
    code = cli.main(["discover", *FAST, "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["outcome"] == "responses_received"
    assert len(output["devices"]) == 3
    assert output["request_count"] == 1


def test_monitor_demo_single_cycle_reports_added_devices(capsys):
    code = cli.main(["monitor", *FAST, "--cycles", "1", "--interval", "1", "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["interface"] == "mock:demo0"
    assert len(output["cycles"]) == 1
    assert output["cycles"][0]["device_count"] == 3
    assert len(output["changes"]) == 3
    assert all(item["kind"] == "added" for item in output["changes"])


def test_monitor_rejects_a_sub_second_interval(capsys):
    code = cli.main(["monitor", *FAST, "--interval", "0.2"])
    assert code == cli.EXIT_FAILED
    assert "--interval" in capsys.readouterr().err


def test_get_demo_reads_identity(capsys):
    code = cli.main(["get", *FAST, "--mac", DEVICE_MAC, "--preset", "identity", "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["state"] == "response_received"
    assert output["identity"]["name_of_station"] == "line-01.conveyor"
    assert output["blocks"]


def test_signal_demo_is_acknowledged(capsys):
    code = cli.main(["signal", *FAST_SIGNAL, "--mac", DEVICE_MAC, "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["operation"] == "signal"
    assert output["state"] == "acknowledged"
    assert output["block_qualifier"] == 0


def test_set_name_without_safety_flags_is_refused_before_touching_an_interface(capsys):
    # An unknown interface proves that refusal happens before transport creation.
    code = cli.main(
        [
            "set-name",
            "-i",
            "definitely-not-an-interface",
            "--mac",
            DEVICE_MAC,
            "--name",
            "line-02.test",
        ]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_FAILED
    assert "New NameOfStation: line-02.test" in captured.out
    assert "No automatic retry or rollback is performed." in captured.out
    assert "--confirm" in captured.err
    assert "Nothing was transmitted" in captured.err
    assert "Unknown interface" not in captured.err


def test_set_name_json_refusal_is_machine_readable(capsys):
    code = cli.main(
        [
            "set-name",
            *FAST,
            "--mac",
            DEVICE_MAC,
            "--name",
            "line-02.test",
            "--json",
        ]
    )
    output = _json(capsys)
    assert code == cli.EXIT_FAILED
    assert output["transmitted"] is False
    assert output["missing_safety_flags"] == list(GUARDS)


def test_set_name_stops_when_target_does_not_answer_identify(capsys):
    code = cli.main(
        [
            "set-name",
            *FAST,
            "--mac",
            "02:00:00:00:00:99",
            "--name",
            "line-02.test",
            *GUARDS,
            "--json",
        ]
    )
    output = _json(capsys)
    assert code == cli.EXIT_UNKNOWN
    assert output["state"] == "target_unverified"
    assert output["transmitted"] is False


def test_set_name_guarded_demo_is_read_back(capsys):
    code = cli.main(
        [
            "set-name",
            *FAST,
            "--mac",
            DEVICE_MAC,
            "--name",
            "line-02.test",
            *GUARDS,
            "--json",
        ]
    )
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["state"] == "acknowledged"
    assert output["verification"] == "verified"
    assert output["request_frame_hex"]


def test_reset_mode_8_post_checks_the_target(capsys):
    code = cli.main(["reset", *FAST, "--mac", DEVICE_MAC, "--mode", "8", *GUARDS, "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["state"] == "acknowledged"
    assert output["post_check_state"] == "responded"
    assert output["verification"] == "not_attempted"


def test_legacy_reset_post_checks_the_target(capsys):
    code = cli.main(
        ["reset", *FAST, "--mac", DEVICE_MAC, "--legacy", *GUARDS, "--json"]
    )
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["state"] == "acknowledged"
    assert output["post_check_state"] == "responded"
    assert output["block_qualifier"] == 0


def test_reset_refuses_unverified_mode():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["reset", "--mac", DEVICE_MAC, "--mode", "3", *GUARDS])
    assert excinfo.value.code == 2


def test_tests_runs_only_read_only_cases(capsys):
    code = cli.main(
        [
            "tests",
            *FAST,
            "--select",
            "parser.fixture_decode",
            "--select",
            "validation.station_name",
            "--json",
        ]
    )
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert {result["test_id"] for result in output["results"]} == {
        "parser.fixture_decode",
        "validation.station_name",
    }
    assert output["summary"]["passed"] == 2


def test_tests_refuses_guarded_test_ids_without_include_writes(capsys):
    code = cli.main(["tests", "--select", "write.set_name"])
    captured = capsys.readouterr()
    assert code == cli.EXIT_FAILED
    assert "--include-writes" in captured.err
    assert "dcp-cli set-name" in captured.err


def test_tests_include_writes_requires_confirm(capsys):
    code = cli.main(
        [
            "tests",
            *FAST,
            "--include-writes",
            "--mac",
            DEVICE_MAC,
            "--select",
            "write.set_name",
        ]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_FAILED
    assert "--confirm" in captured.err


def test_tests_include_writes_runs_a_set_name_against_the_declared_device(capsys):
    code = cli.main(
        [
            "tests",
            *FAST,
            "--include-writes",
            "--confirm",
            "--mac",
            DEVICE_MAC,
            "--name",
            "line-88.cli",
            "--select",
            "write.set_name",
            "--json",
        ]
    )
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["results"][0]["test_id"] == "write.set_name"
    assert output["results"][0]["status"] == "passed"
    assert output["results"][0]["evidence"]["write"]["verification"] == "verified"


def test_discover_writes_json_report(tmp_path, capsys):
    report = tmp_path / "discover.json"
    code = cli.main(["discover", *FAST, "--report", str(report), "--json"])
    _json(capsys)
    assert code == cli.EXIT_OK
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["latest_discovery"]["outcome"] == "responses_received"
    assert payload["test_configuration"]["interface"]["id"] == "mock:demo0"


def test_pcap_analysis_decodes_fixture(tmp_path, capsys):
    path = tmp_path / "fixture.pcap"
    write_pcap(
        path,
        [
            CapturedFrame(
                timestamp=utc_now(),
                interface_id="fixture",
                direction="rx",
                raw=get_fixture("identify_response_named"),
            )
        ],
    )
    code = cli.main(["pcap", str(path), "--dcp-only", "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert len(output) == 1
    assert output[0]["frame"]["kind"] == "dcp"
    assert output[0]["frame"]["xid"] == 0x11223344


def test_inventory_exports_a_csv_of_the_discovered_devices(tmp_path, capsys):
    csv_path = tmp_path / "inventory.csv"
    code = cli.main(["inventory", *FAST, "--csv", str(csv_path), "--json"])
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert len(output["devices"]) == 3
    assert output["csv_path"] == str(csv_path)
    assert output["plan"] is None
    text = csv_path.read_text(encoding="utf-8")
    assert text.splitlines()[0].startswith("mac,name_of_station")
    assert "line-01.conveyor" in text


def test_inventory_plan_check_passes_for_a_matching_plan(tmp_path, capsys):
    plan = tmp_path / "plan.csv"
    plan.write_text(
        "mac,name,ip\n"
        "02:00:00:00:00:11,line-01.conveyor,192.0.2.11\n"
        "02:00:00:00:00:12,line-01.robot,192.0.2.12\n"
        "02:00:00:00:00:13,,\n",
        encoding="utf-8",
    )
    code = cli.main(
        ["inventory", *FAST, "--plan", str(plan), "--strict", "--json"]
    )
    output = _json(capsys)
    assert code == cli.EXIT_OK
    assert output["plan"]["findings"] == []


def test_inventory_plan_check_reports_findings_and_strict_exit(tmp_path, capsys):
    plan = tmp_path / "plan.csv"
    plan.write_text(
        "mac,name,ip\n02:00:00:00:00:11,line-99.wrong,192.0.2.99\n",
        encoding="utf-8",
    )
    code = cli.main(
        ["inventory", *FAST, "--plan", str(plan), "--strict", "--json"]
    )
    output = _json(capsys)
    assert code == cli.EXIT_FAILED
    kinds = [finding["kind"] for finding in output["plan"]["findings"]]
    assert "name_mismatch" in kinds
    assert "ip_mismatch" in kinds
    assert kinds.count("unexpected_device") == 2

    without_strict = cli.main(["inventory", *FAST, "--plan", str(plan), "--json"])
    _json(capsys)
    assert without_strict == cli.EXIT_OK
