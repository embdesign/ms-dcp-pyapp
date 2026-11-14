"""Rendering helpers used by the Qt UI (pure, no QApplication needed)."""

from __future__ import annotations

from datetime import UTC, datetime

from dcpstudio.gui.presentation import (
    device_summary_html,
    display_addr,
    get_result_html,
    report_preview_html,
    signal_result_html,
    write_result_html,
)
from dcpstudio.model import DcpBlock, DeviceIdentity, GetResult, WriteResult

TS = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _device(**overrides) -> DeviceIdentity:
    values = dict(
        interface_id="if0",
        mac="02:00:00:00:00:11",
        first_seen=TS,
        last_seen=TS,
        name_of_station="line-01.conveyor",
        ip_address="192.0.2.11",
        subnet_mask="255.255.255.0",
        gateway="192.0.2.1",
        vendor_id=0x002A,
        device_id=0x0101,
        vendor_name="Mock Automation",
        device_role_flags=0x01,
    )
    values.update(overrides)
    return DeviceIdentity(**values)


def _get_result(**overrides) -> GetResult:
    values = dict(
        interface_id="if0",
        xid=0x11223344,
        target_mac="02:00:00:00:00:11",
        selectors=[(2, 2)],
        started_at=TS,
        finished_at=TS,
        timeout_s=2.0,
        vlan_id=None,
        state="response_received",
    )
    values.update(overrides)
    return GetResult(**values)


def _write_result(**overrides) -> WriteResult:
    values = dict(
        interface_id="if0",
        xid=0x55667788,
        target_mac="02:00:00:00:00:11",
        operation="reset",
        operation_text="ResetToFactorySettings",
        parameters={},
        started_at=TS,
        finished_at=TS,
        timeout_s=2.0,
        vlan_id=None,
        state="acknowledged",
    )
    values.update(overrides)
    return WriteResult(**values)


def test_display_addr_hides_unset_values():
    assert display_addr(None) == "—"
    assert display_addr("0.0.0.0") == "—"
    assert display_addr("192.0.2.1") == "192.0.2.1"


def test_get_result_html_reports_blocks_and_errors():
    ok = get_result_html(
        _get_result(
            blocks=[DcpBlock(option=2, suboption=2, block_length=4, offset=0, value=b"dut")]
        )
    )
    assert "#155c38" in ok
    assert "NameOfStation" in ok

    failed = get_result_html(_get_result(state="no_response"))
    assert "#8c1d12" in failed

    rejected = get_result_html(
        _get_result(
            blocks=[],
            block_errors=[
                DcpBlock(
                    option=2,
                    suboption=2,
                    block_length=4,
                    offset=0,
                    value=b"",
                    block_error=0x05,
                )
            ],
        )
    )
    assert "Block errors" in rejected


def test_write_result_html_shows_verification_and_post_check():
    html = write_result_html(
        _write_result(
            block_qualifier=0x0010,
            rtt_ms=2.5,
            verification="not_attempted",
            verification_detail="Reset acknowledgement is not proof of completion.",
            post_check_state="responded",
            post_check_detail="Device answered.",
            warnings=["No automatic retry performed."],
        )
    )
    assert "qualifier <code>0x0010</code>" in html
    assert "Independent verification" in html
    assert "Post-check (responded)" in html
    assert "Notes:" in html


def test_signal_result_html_is_one_short_line():
    """Signal is observed by the operator, so no guarded-write vocabulary."""
    html = signal_result_html(
        _write_result(
            operation="signal",
            operation_text="Signal device (flash LED)",
            block_qualifier=0,
            block_error=0x00,
            rtt_ms=32.44,
            verification="not_attempted",
            verification_detail=(
                "A Signal acknowledgement means the device accepted the request."
            ),
        )
    )
    assert "Signal acknowledged" in html
    assert "0x55667788" not in html  # no Xid noise
    assert "qualifier" not in html
    assert "Independent verification" not in html
    assert "No independent read-back" not in html
    assert "RTT 32.4 ms" in html
    assert "the only confirmation" in html


def test_signal_result_html_keeps_outcome_unknown_wording():
    html = signal_result_html(
        _write_result(
            operation="signal",
            operation_text="Signal device (flash LED)",
            state="no_response",
            warnings=["No matching response arrived; the outcome is unknown."],
        )
    )
    assert "outcome unknown" in html
    assert "#744800" in html  # warning colour, not failure
    assert "No frame was retried" in html


def test_signal_result_html_reports_blocked_without_retry():
    html = signal_result_html(
        _write_result(
            operation="signal",
            operation_text="Signal device (flash LED)",
            state="blocked",
            error="Passive capture is not running",
            warnings=["No frame was transmitted."],
        )
    )
    assert "blocked" in html.lower()
    assert "Passive capture is not running" in html
    assert "No frame was transmitted." in html


def test_device_summary_escapes_user_visible_text_once():
    html = device_summary_html(
        _device(vendor_name="Mock <Automation>", warnings=("odd <value>",))
    )
    assert "Mock &lt;Automation&gt;" in html
    # The old inline implementation escaped twice and displayed "&lt;".
    assert "&amp;lt;" not in html
    assert "odd &lt;value&gt;" in html


def test_device_summary_reports_ip_block_info_bits():
    html = device_summary_html(_device(ip_block_info=0x0083))
    assert "IP BlockInfo" in html
    assert "IP set" in html
    assert "DHCP" in html
    assert "address conflict indicated" in html


def test_report_preview_counts_and_escapes():
    html = report_preview_html(
        interface_name="eth<0>",
        capture_total=3,
        devices=[_device()],
        get_count=2,
        write_count=1,
        status_counts={"passed": 4, "failed": 0, "skipped": 1, "inconclusive": 2},
        limitations=["Not a conformance certificate"],
        sensitive_warning="Captures contain MAC addresses",
    )
    assert "eth&lt;0&gt;" in html
    assert "Capture frames:</b> 3" in html
    assert "Read-only Get operations:</b> 2" in html
    assert "passed 4, failed 0, skipped 1, inconclusive 2" in html
    assert "02:00:00:00:00:11" in html
    assert "Sensitive data" in html


def test_report_preview_handles_no_devices_and_no_interface():
    html = report_preview_html(
        interface_name=None,
        capture_total=0,
        devices=[],
        get_count=0,
        write_count=0,
        status_counts={},
        limitations=[],
        sensitive_warning="warn",
    )
    assert "No devices discovered." in html
    assert "Interface:</b> none" in html
    assert "passed 0, failed 0, skipped 0, inconclusive 0" in html
