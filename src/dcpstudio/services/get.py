"""Read-only DCP Get transactions with Xid/target correlation.

A Get request is a single read-only transaction containing a list of
Option/SubOption selectors. The service sends exactly one request, waits for one
matching response, and never retries.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from ..codec import build_get_request, extract_device_identity, new_xid, parse_frame
from ..constants import (
    DEFAULT_MIN_REQUEST_INTERVAL_S,
    SUBOPTION_NAMES,
    ControlSubOption,
    DeviceSubOption,
    FrameId,
    IpSubOption,
    Option,
    ServiceId,
    ServiceType,
)
from ..model import DcpFrame, GetResult, TransactionRecord, iso_utc, utc_now
from ..outcomes import RequestState, TransactionOutcome
from ..transport.base import CaptureNotStarted, DcpTransport, TransportError
from .correlation import PendingRequest, decide_frame, wait_for_response
from .discovery import LATE_RESPONSE_GRACE_S
from .rate_limit import RequestRateLimiter

EventLog = Callable[[str, str, dict], None]

ALL_SELECTORS: tuple[tuple[int, int], ...] = (
    (int(Option.IP), int(IpSubOption.MAC)),
    (int(Option.IP), int(IpSubOption.IP_PARAMETER)),
    (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.VENDOR)),
    (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.NAME_OF_STATION)),
    (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ID)),
    (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ROLE)),
    (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_OPTIONS)),
    (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.ALIAS)),
    (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_INSTANCE)),
    (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.OEM_DEVICE_ID)),
    (int(Option.DEVICE_INITIATIVE), 0x01),
)


@dataclass(frozen=True, slots=True)
class GetPreset:
    key: str
    label: str
    selectors: tuple[tuple[int, int], ...]


GET_PRESETS: dict[str, GetPreset] = {
    "identity": GetPreset(
        "identity",
        "Identity essentials (IP, name, ID, role, options, vendor)",
        (
            (int(Option.IP), int(IpSubOption.IP_PARAMETER)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.NAME_OF_STATION)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ID)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ROLE)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_OPTIONS)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.VENDOR)),
        ),
    ),
    "ip": GetPreset(
        "ip",
        "IP parameters + MAC",
        (
            (int(Option.IP), int(IpSubOption.MAC)),
            (int(Option.IP), int(IpSubOption.IP_PARAMETER)),
        ),
    ),
    "name": GetPreset(
        "name",
        "NameOfStation",
        ((int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.NAME_OF_STATION)),),
    ),
    "id_role": GetPreset(
        "id_role",
        "Device ID + role",
        (
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ID)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ROLE)),
        ),
    ),
    "options": GetPreset(
        "options",
        "Advertised DCP options",
        ((int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_OPTIONS)),),
    ),
    "diagnostics": GetPreset(
        "diagnostics",
        "All supported blocks / optional diagnostics",
        ALL_SELECTORS,
    ),
}


def selector_name(selector: tuple[int, int]) -> str:
    return SUBOPTION_NAMES.get(selector, f"0x{selector[0]:02x}/0x{selector[1]:02x}")


@dataclass(slots=True)
class GetConfig:
    timeout_s: float = 2.0
    vlan_id: int | None = None
    selectors: tuple[tuple[int, int], ...] = GET_PRESETS["identity"].selectors
    min_request_interval_s: float = DEFAULT_MIN_REQUEST_INTERVAL_S


class GetService:
    """One-shot read-only Get dispatcher.

    Register :meth:`process_frame` with the same ``FrameRouter`` used by
    discovery. Only one Get transaction is pending at a time.
    """

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

    @property
    def has_pending(self) -> bool:
        with self._lock:
            return self._pending is not None

    def _log(self, event: str, message: str, detail: dict | None = None) -> None:
        if self.event_log is not None:
            try:
                self.event_log(event, message, detail or {})
            except Exception:
                pass

    def _record(self, pending: PendingRequest, **kwargs) -> None:
        pending.transactions.append(TransactionRecord(**kwargs))

    # ------------------------------------------------------------- callbacks
    def process_frame(self, raw: bytes, timestamp: datetime, direction: str) -> None:
        if direction != "rx":
            return
        with self._lock:
            if self._pending is None:
                return

        frame = parse_frame(raw, captured_at=timestamp, interface_id=self.transport.interface.id)
        if (
            frame.kind != "dcp"
            or frame.frame_id != int(FrameId.GET_SET)
            or frame.service_id != int(ServiceId.GET)
            or frame.service_type
            not in (int(ServiceType.RESPONSE_SUCCESS), int(ServiceType.RESPONSE_NOT_SUPPORTED))
        ):
            return

        local_mac = (self.transport.interface.mac or "").lower()
        with self._lock:
            pending = self._pending
            if pending is None:
                return
            decision = decide_frame(
                pending,
                frame,
                timestamp,
                interface_id=self.transport.interface.id,
                local_mac=local_mac,
                label="Get",
                service="Get",
                event="get_response",
                duplicate_detail="A Get response was already received for this Xid",
            )
            if decision is not None:
                return

            block_errors = self._block_errors(frame)
            pending.mark_response(frame, timestamp)
            self._record(
                pending,
                timestamp=timestamp,
                event="get_response",
                interface_id=self.transport.interface.id,
                outcome=(
                    TransactionOutcome.LATE_RESPONSE
                    if pending.late
                    else TransactionOutcome.MATCHING_RESPONSE_RECEIVED
                ),
                detail=(
                    f"{len(frame.blocks)} block(s), {len(block_errors)} block error(s), "
                    f"service type 0x{frame.service_type:02x}"
                ),
                xid=pending.xid,
                service="Get",
                peer_mac=frame.src_mac,
                frame_id=frame.frame_id,
                rtt_ms=pending.rtt_ms,
                raw_hex=frame.raw.hex(),
            )
            pending.notify_response()

    @staticmethod
    def _block_errors(frame: DcpFrame):
        return [
            block
            for block in frame.blocks
            if block.option == int(Option.CONTROL)
            and block.suboption == int(ControlSubOption.RESPONSE)
        ]

    # ------------------------------------------------------------------- get
    def get(
        self,
        target_mac: str,
        config: GetConfig | None = None,
        *,
        cancel_event: threading.Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> GetResult:
        cfg = config or GetConfig()
        cancel_event = cancel_event or threading.Event()
        interface = self.transport.interface
        started = utc_now()
        xid = new_xid()
        selectors = tuple(cfg.selectors)
        request_hex = ""

        if not self.transport.is_capturing:
            raise CaptureNotStarted(
                "Passive capture is not running. Start capture on the selected interface first."
            )
        if not interface.mac:
            raise TransportError("Selected interface has no MAC address")
        if not 0.5 <= float(cfg.timeout_s) <= 60.0:
            raise TransportError("Get timeout must be 0.5..60 seconds")
        if not selectors:
            raise TransportError("At least one Get selector is required")

        if progress:
            progress(f"Waiting for request pacing ({self.limiter.remaining_s():.1f} s)…")
        if not self.limiter.wait(cancel_event):
            finished = utc_now()
            return GetResult(
                interface_id=interface.id,
                xid=xid,
                target_mac=target_mac,
                selectors=list(selectors),
                started_at=started,
                finished_at=finished,
                timeout_s=cfg.timeout_s,
                vlan_id=cfg.vlan_id,
                state=RequestState.CANCELLED,
                cancelled=True,
                warnings=["Cancelled before the Get request was transmitted"],
            )

        try:
            request = build_get_request(
                interface.mac,
                target_mac,
                xid,
                selectors,
                vlan_id=cfg.vlan_id,
            )
            request_hex = request.hex()
        except Exception as exc:
            raise TransportError(f"Could not encode Get request: {exc}") from exc

        now_mono = time.monotonic()
        pending = PendingRequest(
            xid=xid,
            target_mac=target_mac,
            deadline_monotonic=now_mono + float(cfg.timeout_s),
            request_monotonic=now_mono,
            request_tx_utc=utc_now(),
        )
        with self._lock:
            if self._pending is not None:
                raise TransportError("Another Get transaction is already pending")
            self._pending = pending

        try:
            self.transport.send_frame(request)
        except Exception as exc:
            with self._lock:
                self._pending = None
            finished = utc_now()
            message = str(exc) if isinstance(exc, TransportError) else f"Transmission failed: {exc}"
            return GetResult(
                interface_id=interface.id,
                xid=xid,
                target_mac=target_mac,
                selectors=list(selectors),
                started_at=started,
                finished_at=finished,
                timeout_s=cfg.timeout_s,
                vlan_id=cfg.vlan_id,
                state=RequestState.ERROR,
                request_frame_hex=request_hex,
                error=message,
                warnings=["No frame is reported as transmitted"],
            )

        self.limiter.note_sent()
        with self._lock:
            self._record(
                pending,
                timestamp=pending.request_tx_utc,
                event="get_request",
                interface_id=interface.id,
                outcome=TransactionOutcome.TRANSMITTED,
                detail=(
                    f"Get {len(selectors)} block(s): "
                    + ", ".join(selector_name(s) for s in selectors)
                    + f"; timeout {cfg.timeout_s:.1f} s"
                ),
                xid=xid,
                service="Get",
                peer_mac=target_mac,
                frame_id=int(FrameId.GET_SET),
                raw_hex=request_hex,
            )
        self._log(
            "get.request_transmitted",
            f"Get request transmitted (Xid 0x{xid:08x}, {len(selectors)} block(s))",
            {"xid": xid, "target": target_mac, "selectors": [selector_name(s) for s in selectors]},
        )

        wait_for_response(
            pending,
            cancel_event,
            grace_s=LATE_RESPONSE_GRACE_S,
            progress=progress,
            progress_text=lambda remaining: (
                f"Waiting for Get response… {remaining:.1f} s remaining"
            ),
        )

        cancelled = cancel_event.is_set()
        with self._lock:
            self._pending = None
            response = pending.response
            transactions = pending.ordered_transactions()
            unmatched = pending.unmatched_responses
            duplicate = pending.duplicate_responses

        finished = utc_now()
        blocks = list(response.blocks) if response else []
        block_errors = self._block_errors(response) if response else []
        identity = (
            extract_device_identity(response, response_time_ms=pending.rtt_ms)
            if response is not None and response.service_type == int(ServiceType.RESPONSE_SUCCESS)
            else None
        )

        if response is None:
            state = RequestState.CANCELLED if cancelled else RequestState.NO_RESPONSE
        elif response.service_type == int(ServiceType.RESPONSE_NOT_SUPPORTED):
            state = RequestState.SERVICE_NOT_SUPPORTED
        elif pending.late:
            state = RequestState.LATE_RESPONSE
        else:
            state = RequestState.RESPONSE_RECEIVED

        warnings: list[str] = []
        if state == "no_response":
            warnings.append(
                "No matching Get response was observed. This does not prove that the "
                "requested block(s) are unsupported or that the device is absent."
            )
            transactions.append(
                TransactionRecord(
                    timestamp=finished,
                    event="get_timeout",
                    interface_id=interface.id,
                    outcome=TransactionOutcome.OUTCOME_UNKNOWN,
                    detail="No matching Get response within the configured window",
                    xid=xid,
                    service="Get",
                    peer_mac=target_mac,
                    frame_id=int(FrameId.GET_SET),
                )
            )
        if state == "service_not_supported":
            warnings.append("The device returned ServiceType 0x05 for DCP Get.")
        if pending.late:
            warnings.append("The Get response arrived after the configured timeout.")
        if block_errors:
            warnings.append(
                f"{len(block_errors)} requested block(s) were rejected: "
                + "; ".join(
                    f"{selector_name((b.error_option or 0, b.error_suboption or 0))} -> "
                    f"{b.error_text or 'unknown error'}"
                    for b in block_errors
                )
            )
        if cancelled:
            warnings.append("The Get request was cancelled; the result is partial.")
        if unmatched:
            warnings.append(f"{unmatched} unrelated response(s) were ignored (Xid/target mismatch).")
        if duplicate:
            warnings.append(f"{duplicate} duplicate Get response(s) were ignored.")

        result = GetResult(
            interface_id=interface.id,
            xid=xid,
            target_mac=target_mac,
            selectors=list(selectors),
            started_at=started,
            finished_at=finished,
            timeout_s=cfg.timeout_s,
            vlan_id=cfg.vlan_id,
            state=state,
            request_frame_hex=request_hex,
            response_frame_hex=response.raw.hex() if response else "",
            blocks=blocks,
            block_errors=block_errors,
            identity=identity,
            transactions=transactions,
            rtt_ms=pending.rtt_ms,
            late=pending.late,
            cancelled=cancelled,
            warnings=warnings,
        )
        self._log(
            "get.finished",
            result.outcome_text,
            {
                "xid": xid,
                "target": target_mac,
                "state": state,
                "duration_ms": round(result.duration_ms, 3),
                "blocks": len(blocks),
                "block_errors": len(block_errors),
                "started": iso_utc(started),
                "finished": iso_utc(finished),
            },
        )
        return result
