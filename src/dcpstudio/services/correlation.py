"""Shared transaction correlation for the one-request/one-response services.

Discovery, Get, Write and Signal each wait for the response to one transmitted
request. The mechanism — pending record, deadline and grace, RTT, late and
duplicate/unmatched counters, transaction ordering, the wait loop — was copied
into every service. This module owns the mechanism; each service keeps only its
matching policy and its own transaction text.

Two kinds of wait exist:

* :func:`wait_for_response` — stop as soon as the first matching response
  arrives (Get, Write, Signal);
* :func:`collect_until_deadline` — keep collecting until the deadline, because
  Identify legitimately produces many responses (Discovery).

Both share the same deadline/grace/cancellation arithmetic.

Pure logic: no transport, no Qt, no sockets. The clock is ``time.monotonic``.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from ..model import DcpFrame, TransactionRecord
from ..outcomes import TransactionOutcome

ProgressCallback = Callable[[str], None]
ProgressText = Callable[[float], str]
ExtraCheck = Callable[["PendingRequest", DcpFrame], str | None]

_LOOP_INTERVAL_S = 0.05
_PROGRESS_INTERVAL_S = 0.25


class MatchResult(StrEnum):
    """Why a frame did not become the pending request's response."""

    UNRELATED = "unrelated"
    DUPLICATE = "duplicate"


@dataclass(slots=True)
class PendingRequest:
    """One in-flight request and everything its waiter needs."""

    xid: int
    target_mac: str | None
    deadline_monotonic: float
    request_monotonic: float
    request_tx_utc: datetime
    response: DcpFrame | None = None
    response_timestamp: datetime | None = None
    rtt_ms: float | None = None
    late: bool = False
    duplicate_responses: int = 0
    unmatched_responses: int = 0
    transactions: list[TransactionRecord] = field(default_factory=list)
    response_event: threading.Event = field(default_factory=threading.Event)

    def mark_response(self, frame: DcpFrame, timestamp: datetime) -> None:
        """Store the first matching response.

        Does **not** wake the waiter: the caller records the response first so a
        woken waiter can never observe the response without its transaction.
        """
        now = time.monotonic()
        self.response = frame
        self.response_timestamp = timestamp
        self.rtt_ms = round(max(0.0, (now - self.request_monotonic) * 1000.0), 3)
        self.late = now > self.deadline_monotonic

    def notify_response(self) -> None:
        self.response_event.set()

    def ordered_transactions(self) -> list[TransactionRecord]:
        """Transactions in time order, ties broken by kind.

        Windows' clock granularity can make the request and a fast response
        share a timestamp, so a pure timestamp sort is not stable enough.
        """
        return sorted(
            self.transactions,
            key=lambda record: (
                record.timestamp,
                0 if record.outcome == TransactionOutcome.TRANSMITTED else 1,
            ),
        )


def decide_frame(
    pending: PendingRequest,
    frame: DcpFrame,
    timestamp: datetime,
    *,
    interface_id: str,
    local_mac: str,
    label: str,
    service: str,
    event: str,
    duplicate_detail: str,
    extra_check: ExtraCheck | None = None,
) -> MatchResult | None:
    """Record frames that are *not* the first matching response.

    Returns ``None`` when the frame is the first matching response; the caller
    then records it and calls :meth:`PendingRequest.mark_response` followed by
    :meth:`PendingRequest.notify_response`.

    The caller has already applied its own frame pre-filter (kind, FrameID,
    ServiceID, response type). This function applies the checks every
    one-response service shares: destination, Xid, source, an optional
    service-specific check, and duplicate suppression.
    """
    target = pending.target_mac or ""

    def record(outcome: str, detail: str, *, xid: int | None) -> None:
        pending.transactions.append(
            TransactionRecord(
                timestamp=timestamp,
                event=event,
                interface_id=interface_id,
                outcome=outcome,
                detail=detail,
                xid=xid,
                service=service,
                peer_mac=frame.src_mac,
                frame_id=frame.frame_id,
                raw_hex=frame.raw.hex(),
            )
        )

    if (
        local_mac
        and frame.dst_mac
        and frame.dst_mac.lower() not in (local_mac, "ff:ff:ff:ff:ff:ff")
    ):
        # A response addressed to another requester is not ours, even if the
        # 32-bit Xid happens to collide.
        if frame.xid == pending.xid:
            pending.unmatched_responses += 1
            record(
                TransactionOutcome.UNRELATED_RESPONSE_IGNORED,
                f"{label} response destination {frame.dst_mac} is not this interface",
                xid=frame.xid,
            )
        return MatchResult.UNRELATED

    if frame.xid != pending.xid:
        pending.unmatched_responses += 1
        record(
            TransactionOutcome.UNRELATED_RESPONSE_IGNORED,
            f"{label} response Xid 0x{(frame.xid or 0):08x} does not match request",
            xid=frame.xid,
        )
        return MatchResult.UNRELATED

    if (frame.src_mac or "").lower() != target.lower():
        pending.unmatched_responses += 1
        record(
            TransactionOutcome.UNRELATED_RESPONSE_IGNORED,
            f"{label} target was {target}, response came from {frame.src_mac}",
            xid=pending.xid,
        )
        return MatchResult.UNRELATED

    if pending.response is not None:
        pending.duplicate_responses += 1
        record(
            TransactionOutcome.DUPLICATE_RESPONSE_IGNORED,
            duplicate_detail,
            xid=pending.xid,
        )
        return MatchResult.DUPLICATE

    if extra_check is not None:
        detail = extra_check(pending, frame)
        if detail is not None:
            pending.unmatched_responses += 1
            record(TransactionOutcome.UNRELATED_RESPONSE_IGNORED, detail, xid=pending.xid)
            return MatchResult.UNRELATED

    return None


def wait_for_response(
    pending: PendingRequest,
    cancel_event: threading.Event,
    *,
    grace_s: float,
    progress: ProgressCallback | None = None,
    progress_text: ProgressText | None = None,
) -> None:
    """Wait until the first response, cancellation, or deadline + grace."""
    last_progress = 0.0
    while True:
        if cancel_event.is_set():
            break
        remaining = pending.deadline_monotonic - time.monotonic()
        if remaining <= -grace_s:
            break
        waiting = min(_LOOP_INTERVAL_S, max(0.0, remaining) if remaining > 0 else 0.02)
        if pending.response_event.wait(waiting):
            break
        if (
            progress
            and progress_text
            and remaining > 0
            and (time.monotonic() - last_progress) > _PROGRESS_INTERVAL_S
        ):
            last_progress = time.monotonic()
            progress(progress_text(remaining))


def collect_until_deadline(
    pending: PendingRequest,
    cancel_event: threading.Event,
    *,
    grace_s: float,
    progress: ProgressCallback | None = None,
    progress_text: ProgressText | None = None,
) -> None:
    """Poll until cancellation or deadline + grace, collecting many responses."""
    last_progress = 0.0
    while True:
        if cancel_event.is_set():
            break
        remaining = pending.deadline_monotonic - time.monotonic()
        if remaining <= -grace_s:
            break
        if (
            progress
            and progress_text
            and remaining > 0
            and (time.monotonic() - last_progress) > _PROGRESS_INTERVAL_S
        ):
            last_progress = time.monotonic()
            progress(progress_text(remaining))
        time.sleep(min(_LOOP_INTERVAL_S, max(0.0, remaining) if remaining > 0 else 0.02))
