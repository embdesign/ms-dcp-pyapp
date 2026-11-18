"""One-shot DCP Signal (option 05 / sub-option 03): flash the identification LED.

Signal is an **identification aid, not a configuration change**: it stores
nothing, interrupts nothing, and cannot move the device into another state. It
is therefore deliberately **outside** the guarded write path in
``services/write.py`` — no configuration mode, no authorization dialog, no
safe-maintenance attestation and no target revalidation.

What is still enforced here:

* one unicast request per call — never multicast or broadcast;
* exactly one transmission, no automatic retry;
* the shared conservative request-rate limit;
* correlation by FrameID + ServiceID/ServiceType + Xid + source MAC;
* the standard outcome vocabulary: ``acknowledged`` / ``rejected`` /
  ``no_response`` (outcome unknown) — a missing response proves nothing.

The wire format is verified in Wireshark's ``pn_dcp`` dissector (IEC 61158-6-10
section 4.3): 2-byte BlockQualifier + 2-byte SignalValue, ``0x0100`` = "Flash
Once". p-net ignores both fields and just flashes the LED, so the same block is
accepted by p-net-based devices as well.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import datetime

from ..codec import build_signal_request, classify_set_response, new_xid, parse_frame
from ..constants import ServiceId
from ..model import TransactionRecord, WriteResult, utc_now
from ..outcomes import RequestState, ResponseVerdict, TransactionOutcome
from ..transport.base import DcpTransport, TransportError
from .correlation import PendingRequest, wait_for_response
from .rate_limit import RequestRateLimiter

EventLog = Callable[[str, str, dict], None]

OPERATION_TEXT = "Signal device (flash LED)"

# A response that arrives this long after the deadline is still matched (and
# reported as late) instead of being silently dropped.
_LATE_RESPONSE_GRACE_S = 0.15


class SignalService:
    """Unicast Control/Signal dispatcher (not a guarded write)."""

    def __init__(
        self,
        transport: DcpTransport,
        *,
        limiter: RequestRateLimiter | None = None,
        event_log: EventLog | None = None,
    ) -> None:
        self.transport = transport
        self.limiter = limiter or RequestRateLimiter()
        self.event_log = event_log
        self._lock = threading.Lock()
        self._pending: PendingRequest | None = None

    # ---------------------------------------------------------------- frames
    def process_frame(self, raw: bytes, timestamp: datetime, direction: str) -> None:
        """Correlate a Set response with the pending Signal request."""
        if direction != "rx" or not raw:
            return
        try:
            frame = parse_frame(
                raw,
                captured_at=timestamp,
                interface_id=self.transport.interface.id,
                direction=direction,
            )
        except Exception:
            return
        with self._lock:
            pending = self._pending
            if pending is None or frame.xid != pending.xid:
                return
            if (frame.src_mac or "").lower() != (pending.target_mac or "").lower():
                return
            if frame.service_id != int(ServiceId.SET):
                return
            if pending.response is not None:
                return  # first matching response wins; duplicates are ignored
            pending.mark_response(frame, timestamp)
            pending.notify_response()

    # ----------------------------------------------------------------- action
    def signal(
        self,
        target_mac: str,
        *,
        timeout_s: float = 2.0,
        vlan_id: int | None = None,
        cancel_event: threading.Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> WriteResult:
        """Transmit exactly one Signal request to one unicast device."""
        cancel_event = cancel_event or threading.Event()
        started = utc_now()
        xid = new_xid()
        result = WriteResult(
            interface_id=self.transport.interface.id,
            xid=xid,
            target_mac=target_mac,
            operation="signal",
            operation_text=OPERATION_TEXT,
            parameters={"Option / sub-option": "05 / 03", "SignalValue": "0x0100"},
            started_at=started,
            finished_at=started,
            timeout_s=float(timeout_s),
            vlan_id=vlan_id,
            block_qualifier=0,
            verification="not_attempted",
            verification_detail=(
                "A Signal acknowledgement means the device accepted the request. The LED "
                "behaviour itself cannot be verified over DCP, and Signal changes no "
                "stored configuration."
            ),
        )

        src_mac = self.transport.interface.mac or ""
        try:
            raw_request = build_signal_request(
                src_mac, target_mac, xid, vlan_id=vlan_id
            )
        except Exception as exc:
            result.state = RequestState.BLOCKED
            result.error = f"Could not encode the request: {exc}"
            result.finished_at = utc_now()
            result.warnings.append("No frame was transmitted.")
            return result
        result.request_frame_hex = raw_request.hex()

        if not self.transport.is_capturing:
            result.state = RequestState.BLOCKED
            result.error = "Passive capture is not running"
            result.finished_at = utc_now()
            result.warnings.append("No frame was transmitted.")
            return result
        if not src_mac:
            result.state = RequestState.BLOCKED
            result.error = "Selected interface has no MAC address"
            result.finished_at = utc_now()
            result.warnings.append("No frame was transmitted.")
            return result

        if progress:
            progress(f"Waiting for request pacing ({self.limiter.remaining_s():.1f} s)…")
        if not self.limiter.wait(cancel_event):
            result.state = RequestState.CANCELLED
            result.cancelled = True
            result.finished_at = utc_now()
            result.warnings.append("Cancelled before the Signal frame was transmitted.")
            return result

        pending = PendingRequest(
            xid=xid,
            target_mac=target_mac,
            deadline_monotonic=time.monotonic() + float(timeout_s),
            request_monotonic=time.monotonic(),
            request_tx_utc=utc_now(),
        )
        with self._lock:
            if self._pending is not None:
                result.state = RequestState.ERROR
                result.error = "Another Signal request is already pending"
                result.finished_at = utc_now()
                return result
            self._pending = pending

        try:
            self.transport.send_frame(raw_request)
        except Exception as exc:
            with self._lock:
                self._pending = None
            result.state = RequestState.ERROR
            result.error = (
                str(exc) if isinstance(exc, TransportError) else f"Transmission failed: {exc}"
            )
            result.finished_at = utc_now()
            result.warnings.append("No frame is reported as transmitted.")
            return result

        result.transmitted = True
        self.limiter.note_sent()
        result.transactions.append(
            TransactionRecord(
                timestamp=pending.request_tx_utc,
                event="signal_request",
                interface_id=self.transport.interface.id,
                outcome=TransactionOutcome.TRANSMITTED,
                detail=f"{OPERATION_TEXT}; SignalValue 0x0100; no retry",
                xid=xid,
                service="Set",
                peer_mac=target_mac,
                frame_id=0xFEFD,
                raw_hex=raw_request.hex(),
            )
        )
        if self.event_log:
            self.event_log(
                "signal.request_transmitted",
                f"{OPERATION_TEXT} transmitted (Xid 0x{xid:08x})",
                {"xid": xid, "target": target_mac, "request_hex": raw_request.hex()},
            )

        wait_for_response(pending, cancel_event, grace_s=_LATE_RESPONSE_GRACE_S)

        with self._lock:
            self._pending = None
            response = pending.response
            rtt_ms = pending.rtt_ms
        result.transactions.extend(pending.transactions)
        result.finished_at = utc_now()
        result.rtt_ms = rtt_ms

        if response is None:
            if cancel_event.is_set():
                result.state = RequestState.CANCELLED
                result.cancelled = True
                result.warnings.append(
                    "Cancelled while waiting. The Signal frame had already been transmitted; "
                    "cancellation does not undo it, and the outcome is unknown."
                )
                outcome = TransactionOutcome.OUTCOME_UNKNOWN
                event = "signal_cancelled"
            else:
                result.state = RequestState.NO_RESPONSE
                outcome = TransactionOutcome.OUTCOME_UNKNOWN
                event = "signal_timeout"
                result.warnings.append(
                    "No matching Set response was observed. This is outcome unknown, not "
                    "proof that the device ignored the request. No automatic retry was "
                    "performed."
                )
            result.transactions.append(
                TransactionRecord(
                    timestamp=result.finished_at,
                    event=event,
                    interface_id=self.transport.interface.id,
                    outcome=outcome,
                    detail=f"No matching Control/Response for {OPERATION_TEXT}",
                    xid=xid,
                    service="Set",
                    peer_mac=target_mac,
                    frame_id=0xFEFD,
                )
            )
            result.transactions.sort(key=lambda record: record.timestamp)
            return result

        result.response_frame_hex = response.raw.hex()
        verdict, error, text = classify_set_response(response)
        result.response_verdict = verdict
        result.block_error = error
        if verdict == ResponseVerdict.ACKNOWLEDGED:
            result.state = RequestState.ACKNOWLEDGED
        elif verdict == ResponseVerdict.REJECTED:
            result.state = RequestState.REJECTED
        elif verdict == ResponseVerdict.SERVICE_NOT_SUPPORTED:
            result.state = RequestState.SERVICE_NOT_SUPPORTED
        else:
            result.state = RequestState.ERROR
            result.error = text
        result.transactions.append(
            TransactionRecord(
                timestamp=pending.response_timestamp or result.finished_at,
                event="signal_response",
                interface_id=self.transport.interface.id,
                outcome=result.state,
                detail=text,
                xid=xid,
                service="Set",
                peer_mac=response.src_mac,
                frame_id=0xFEFD,
                raw_hex=response.raw.hex(),
            )
        )
        result.transactions.sort(key=lambda record: record.timestamp)
        return result
