from __future__ import annotations

import json
from datetime import UTC, datetime

from dcpstudio.config import AppConfig
from dcpstudio.logging_setup import EventLogger
from dcpstudio.model import (
    DeviceIdentity,
    DiscoveryResult,
    GetResult,
    TestResult,
    TransactionRecord,
    WriteResult,
)
from dcpstudio.reporting import (
    SENSITIVE_WARNING,
    ReportContext,
    build_report,
    report_filename,
    write_html_report,
    write_json_report,
)


def _context() -> ReportContext:
    now = datetime(2026, 11, 11, 12, 0, 0, tzinfo=UTC)
    device = DeviceIdentity(
        interface_id="eth0",
        mac="02:00:00:00:00:11",
        first_seen=now,
        last_seen=now,
        name_of_station="<script>alert(1)</script>",
        ip_address="192.0.2.11",
        subnet_mask="255.255.255.0",
        gateway="192.0.2.1",
        vendor_id=0x002A,
        device_id=0x0101,
        response_time_ms=1.5,
        last_response_hex="00",
    )
    result = DiscoveryResult(
        interface_id="eth0",
        xid=0x11223344,
        started_at=now,
        finished_at=now,
        timeout_s=3.0,
        response_delay_factor=50,
        vlan_id=None,
        devices=[device],
        transactions=[
            TransactionRecord(
                timestamp=now,
                event="identify_request",
                interface_id="eth0",
                outcome="transmitted",
                xid=0x11223344,
                service="Identify",
            )
        ],
        warnings=["No matching response was observed. This does not prove that no device exists."],
    )
    test = TestResult(
        test_id="parser.fixture_decode",
        name="Decode fixture",
        category="Offline parser",
        status="passed",
        detail="ok",
        started_at=now,
        duration_ms=1.0,
    )
    get_result = GetResult(
        interface_id="eth0",
        xid=0x55667788,
        target_mac="02:00:00:00:00:11",
        selectors=[(0x01, 0x02)],
        started_at=now,
        finished_at=now,
        timeout_s=2.0,
        vlan_id=None,
        state="response_received",
        rtt_ms=1.25,
    )
    logger = EventLogger()
    logger.info("app.start", "started", {"phase": 4})
    write_result = WriteResult(
        interface_id="eth0",
        xid=0x99AABBCC,
        target_mac="02:00:00:00:00:11",
        operation="set_name",
        operation_text="Set NameOfStation",
        parameters={"NameOfStation": "line-01.conveyor"},
        started_at=now,
        finished_at=now,
        timeout_s=2.0,
        vlan_id=None,
        state="acknowledged",
        permanent=True,
        block_qualifier=0x0001,
        before_identity=device,
        after_identity=device,
        verification="verified",
        verification_detail="Read-back matched.",
    )
    return ReportContext(
        config=AppConfig(),
        discovery=result,
        discoveries=[result],
        get_results=[get_result],
        write_results=[write_result],
        test_results=[test],
        logs=logger.snapshot(),
        capture_stats={"total": 4, "dcp": 4},
    )


def test_json_report_contains_required_sections(tmp_path):
    path = write_json_report(tmp_path / "report.json", _context())
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 2
    assert "phase" not in data["metadata"]
    assert "phase_scope" not in data["metadata"]
    assert data["metadata"]["application"]
    assert data["metadata"]["version"]
    assert data["generated_at"].endswith("Z")
    assert data["sensitive_data_warning"] == SENSITIVE_WARNING
    assert data["test_configuration"]["timeout_s"] == 3.0
    assert data["latest_discovery"]["devices"][0]["mac"] == "02:00:00:00:00:11"
    assert data["get_operations"][0]["target_mac"] == "02:00:00:00:00:11"
    assert data["get_operations"][0]["state"] == "response_received"
    assert data["write_operations"][0]["target_mac"] == "02:00:00:00:00:11"
    assert data["write_operations"][0]["state"] == "acknowledged"
    assert data["write_operations"][0]["verification"] == "verified"
    assert data["before_after_observations"][0]["operation"] == "set_name"
    assert data["test_summary"]["passed"] == 1
    assert data["known_limitations"]
    assert "not an official PROFINET conformance certification" in data["disclaimer"]


def test_html_report_escapes_device_text(tmp_path):
    path = write_html_report(tmp_path / "report.html", _context())
    text = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "Known limitations" in text
    assert "Sensitive data" in text
    assert "Read-only Get operations" in text
    assert "State-changing operations (guarded)" in text


def test_report_filename_is_utc_and_extension_safe():
    name = report_filename("dcp-report", extension="html")
    assert name.startswith("dcp-report-")
    assert name.endswith("Z.html")
    assert all(part.isdigit() or part in "TZ" for part in name[len("dcp-report-") : -len(".html")].replace("-", ""))


def test_build_report_counts_statuses():
    report = build_report(_context())
    assert report["test_summary"] == {
        "passed": 1,
        "failed": 0,
        "skipped": 0,
        "inconclusive": 0,
    }
