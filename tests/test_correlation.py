"""Tests for the shared transaction-correlation primitive."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

from dcpstudio.model import DcpFrame, TransactionRecord
from dcpstudio.services.correlation import (
    MatchResult,
    PendingRequest,
    collect_until_deadline,
    decide_frame,
    wait_for_response,
)

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
LOCAL_MAC = "02:00:00:00:00:01"
TARGET_MAC = "02:00:00:00:00:11"


def _pending(*, response: DcpFrame | None = None, timeout_s: float = 0.5) -> PendingRequest:
    now = time.monotonic()
    pending = PendingRequest(
        xid=0x11223344,
        target_mac=TARGET_MAC,
        deadline_monotonic=now + timeout_s,
        request_monotonic=now,
        request_tx_utc=NOW,
    )
    pending.response = response
    return pending


def _frame(
    *,
    xid: int = 0x11223344,
    src: str = TARGET_MAC,
    dst: str = LOCAL_MAC,
) -> DcpFrame:
    return DcpFrame(
        raw=b"\x01\x02\x03",
        captured_at=NOW,
        dst_mac=dst,
        src_mac=src,
        frame_id=0xFEFD,
        service_id=0x03,
        service_type=0x01,
        xid=xid,
    )


def _decide(pending, frame, *, extra_check=None, local_mac: str = LOCAL_MAC):
    return decide_frame(
        pending,
        frame,
        NOW,
        interface_id="mock:demo0",
        local_mac=local_mac,
        label="Get",
        service="Get",
        event="get_response",
        duplicate_detail="A Get response was already received for this Xid",
        extra_check=extra_check,
    )


# --------------------------------------------------------------- matching
def test_first_matching_frame_is_left_to_the_caller():
    pending = _pending()

    assert _decide(pending, _frame()) is None
    assert pending.transactions == []
    assert pending.unmatched_responses == 0
    assert pending.duplicate_responses == 0


def test_response_for_another_requester_is_unrelated_and_counted():
    pending = _pending()

    result = _decide(pending, _frame(dst="02:00:00:00:00:99"))

    assert result is MatchResult.UNRELATED
    assert pending.unmatched_responses == 1
    assert [record.outcome for record in pending.transactions] == [
        "unrelated_response_ignored"
    ]


def test_foreign_destination_with_foreign_xid_is_not_counted():
    pending = _pending()

    result = _decide(pending, _frame(dst="02:00:00:00:00:99", xid=0xDEADBEEF))

    assert result is MatchResult.UNRELATED
    assert pending.unmatched_responses == 0
    assert pending.transactions == []


def test_xid_mismatch_records_the_frame_xid():
    pending = _pending()

    result = _decide(pending, _frame(xid=0xDEADBEEF))

    assert result is MatchResult.UNRELATED
    assert pending.unmatched_responses == 1
    assert pending.transactions[0].xid == 0xDEADBEEF


def test_source_mismatch_is_unrelated():
    pending = _pending()

    result = _decide(pending, _frame(src="02:00:00:00:00:99"))

    assert result is MatchResult.UNRELATED
    assert pending.unmatched_responses == 1
    assert TARGET_MAC in pending.transactions[0].detail


def test_duplicate_response_is_counted_not_overwritten():
    first = _frame()
    pending = _pending(response=first)

    result = _decide(pending, _frame())

    assert result is MatchResult.DUPLICATE
    assert pending.duplicate_responses == 1
    assert pending.transactions[0].outcome == "duplicate_response_ignored"


def test_extra_check_runs_after_duplicate():
    pending = _pending(response=_frame())
    calls: list[object] = []

    def extra(pending, frame):
        calls.append(frame)
        return "wrong block"

    result = _decide(pending, _frame(), extra_check=extra)

    assert result is MatchResult.DUPLICATE
    assert calls == []


def test_extra_check_reports_unrelated_with_its_detail():
    pending = _pending()

    result = _decide(pending, _frame(), extra_check=lambda *_: "wrong block")

    assert result is MatchResult.UNRELATED
    assert pending.unmatched_responses == 1
    assert pending.transactions[0].detail == "wrong block"


# ------------------------------------------------------------- pending state
def test_mark_response_sets_rtt_and_late_but_does_not_wake():
    now = time.monotonic()
    pending = PendingRequest(
        xid=1,
        target_mac=TARGET_MAC,
        deadline_monotonic=now - 0.01,  # already past
        request_monotonic=now - 0.02,
        request_tx_utc=NOW,
    )

    pending.mark_response(_frame(), NOW)

    assert pending.response is not None
    assert pending.rtt_ms is not None and pending.rtt_ms > 0
    assert pending.late is True
    assert not pending.response_event.is_set()

    pending.notify_response()
    assert pending.response_event.is_set()


def test_ordered_transactions_put_the_request_first_on_a_tie():
    pending = _pending()
    pending.transactions.append(
        TransactionRecord(timestamp=NOW, event="response", interface_id="i", outcome="late")
    )
    pending.transactions.append(
        TransactionRecord(timestamp=NOW, event="request", interface_id="i", outcome="transmitted")
    )

    ordered = pending.ordered_transactions()

    assert [record.outcome for record in ordered] == ["transmitted", "late"]


# --------------------------------------------------------------- wait loops
def test_wait_for_response_wakes_on_notify():
    pending = _pending(timeout_s=5.0)

    def notify() -> None:
        time.sleep(0.02)
        pending.notify_response()

    thread = threading.Thread(target=notify)
    started = time.monotonic()
    thread.start()
    wait_for_response(pending, threading.Event(), grace_s=1.0)
    elapsed = time.monotonic() - started
    thread.join()

    assert elapsed < 1.0


def test_wait_for_response_returns_on_cancel():
    pending = _pending(timeout_s=5.0)
    cancel = threading.Event()
    cancel.set()

    started = time.monotonic()
    wait_for_response(pending, cancel, grace_s=1.0)

    assert time.monotonic() - started < 0.5


def test_wait_for_response_honours_the_late_grace():
    now = time.monotonic()
    pending = PendingRequest(
        xid=1,
        target_mac=TARGET_MAC,
        deadline_monotonic=now - 0.02,
        request_monotonic=now - 0.05,
        request_tx_utc=NOW,
    )

    started = time.monotonic()
    wait_for_response(pending, threading.Event(), grace_s=0.05)

    assert time.monotonic() - started < 0.5


def test_collect_until_deadline_ignores_a_response():
    pending = _pending(response=_frame(), timeout_s=0.06)

    started = time.monotonic()
    collect_until_deadline(pending, threading.Event(), grace_s=0.0)
    elapsed = time.monotonic() - started

    assert elapsed >= 0.04
