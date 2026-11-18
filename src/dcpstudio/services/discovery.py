"""DCP Identify discovery and transaction correlation."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from ..codec import build_identify_request, extract_device_identity, new_xid, parse_frame
from ..constants import (
    DCP_MULTICAST_MAC,
    DEFAULT_MIN_REQUEST_INTERVAL_S,
    DEFAULT_RESPONSE_DELAY_FACTOR,
    FrameId,
    ServiceId,
    ServiceType,
)
from ..model import (
    DeviceIdentity,
    DiscoveryResult,
    TransactionRecord,
    iso_utc,
    utc_now,
)
from ..outcomes import TransactionOutcome
from ..transport.base import CaptureNotStarted, DcpTransport, TransportError
from ..validation import validate_station_name
from .correlation import PendingRequest, collect_until_deadline
from .rate_limit import RequestRateLimiter

EventLog = Callable[[str, str, dict], None]

# A short grace period lets us log a late response distinctly instead of losing
# it at the exact timeout boundary. It does not extend the advertised timeout;
# late responses are marked and warned about.
LATE_RESPONSE_GRACE_S = 0.15


@dataclass(slots=True)
class DiscoveryConfig:
    timeout_s: float = 3.0
    response_delay_factor: int = DEFAULT_RESPONSE_DELAY_FACTOR
    vlan_id: int | None = None
    unicast_mac: str | None = None
    min_request_interval_s: float = DEFAULT_MIN_REQUEST_INTERVAL_S
    identify_filter_name: str | None = None


@dataclass(slots=True)
class _Pending(PendingRequest):
    """An Identify request plus the devices collected for it."""

    devices: dict[tuple[str, str], DeviceIdentity] = field(default_factory=dict)
    late_responses: int = 0


class DiscoveryService:
    """Read-only Identify dispatcher.

    Register :meth:`process_frame` with a ``FrameRouter``. Only one discovery
    request is pending at a time; the service sends exactly one request and does
    not retry.
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
        self._pending: _Pending | None = None

    # ------------------------------------------------------------- callbacks
    def _log(self, event: str, message: str, detail: dict | None = None) -> None:
        if self.event_log is not None:
            try:
                self.event_log(event, message, detail or {})
            except Exception:
                pass

    def _record(self, pending: _Pending, **kwargs) -> None:
        pending.transactions.append(TransactionRecord(**kwargs))

    def process_frame(self, raw: bytes, timestamp: datetime, direction: str) -> None:
        if direction != "rx":
            return
        with self._lock:
            pending = self._pending
            if pending is None:
                return
            xid = pending.xid
            target = pending.target_mac
            deadline = pending.deadline_monotonic
            request_mono = pending.request_monotonic

        frame = parse_frame(raw, captured_at=timestamp, interface_id=self.transport.interface.id)
        if (
            frame.kind != "dcp"
            or frame.frame_id != int(FrameId.IDENTIFY_RESPONSE)
            or frame.service_id != int(ServiceId.IDENTIFY)
            or frame.service_type
            not in (int(ServiceType.RESPONSE_SUCCESS), int(ServiceType.RESPONSE_NOT_SUPPORTED))
        ):
            return

        local_mac = (self.transport.interface.mac or "").lower()
        if local_mac and frame.dst_mac and frame.dst_mac.lower() not in (
            local_mac,
            "ff:ff:ff:ff:ff:ff",
        ):
            # A response addressed to another requester is not ours, even if
            # the 32-bit Xid happens to collide.
            with self._lock:
                pending = self._pending
                if pending is not None and frame.xid == pending.xid:
                    pending.unmatched_responses += 1
                    self._record(
                        pending,
                        timestamp=timestamp,
                        event="identify_response",
                        interface_id=self.transport.interface.id,
                        outcome=TransactionOutcome.UNRELATED_RESPONSE_IGNORED,
                        detail=f"Response destination {frame.dst_mac} is not this interface",
                        xid=frame.xid,
                        service="Identify",
                        peer_mac=frame.src_mac,
                        frame_id=frame.frame_id,
                        raw_hex=frame.raw.hex(),
                    )
            return

        with self._lock:
            pending = self._pending
            if pending is None or pending.xid != xid:
                return
            if frame.xid != xid:
                pending.unmatched_responses += 1
                self._record(
                    pending,
                    timestamp=timestamp,
                    event="identify_response",
                    interface_id=self.transport.interface.id,
                    outcome=TransactionOutcome.UNRELATED_RESPONSE_IGNORED,
                    detail=f"Identify response Xid 0x{(frame.xid or 0):08x} does not match request",
                    xid=frame.xid,
                    service="Identify",
                    peer_mac=frame.src_mac,
                    frame_id=frame.frame_id,
                    raw_hex=frame.raw.hex(),
                )
                return
            if target and (frame.src_mac or "").lower() != target.lower():
                pending.unmatched_responses += 1
                self._record(
                    pending,
                    timestamp=timestamp,
                    event="identify_response",
                    interface_id=self.transport.interface.id,
                    outcome=TransactionOutcome.UNRELATED_RESPONSE_IGNORED,
                    detail=f"Unicast Identify target was {target}, response came from {frame.src_mac}",
                    xid=xid,
                    service="Identify",
                    peer_mac=frame.src_mac,
                    frame_id=frame.frame_id,
                    raw_hex=frame.raw.hex(),
                )
                return

            rtt_ms = max(0.0, (time.monotonic() - request_mono) * 1000.0)
            identity = extract_device_identity(frame, response_time_ms=round(rtt_ms, 3))
            if identity is None:
                return
            late = time.monotonic() > deadline
            if late:
                pending.late_responses += 1
                identity.warnings.append("Response arrived after the configured timeout")

            key = (self.transport.interface.id, identity.mac)
            existing = pending.devices.get(key)
            if existing is None:
                pending.devices[key] = identity
            else:
                existing.merge(identity)
                pending.duplicate_responses += 1

            self._record(
                pending,
                timestamp=timestamp,
                event="identify_response",
                interface_id=self.transport.interface.id,
                outcome=(
                    TransactionOutcome.LATE_RESPONSE
                    if late
                    else TransactionOutcome.MATCHING_RESPONSE_RECEIVED
                ),
                detail=(
                    f"{identity.display_name}, IP {identity.ip_text}, "
                    f"Vendor/Device {identity.vendor_device_text}"
                ),
                xid=xid,
                service="Identify",
                peer_mac=identity.mac,
                frame_id=frame.frame_id,
                rtt_ms=round(rtt_ms, 3),
                raw_hex=frame.raw.hex(),
            )

    # ------------------------------------------------------------- discovery
    def discover(
        self,
        config: DiscoveryConfig | None = None,
        *,
        cancel_event: threading.Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> DiscoveryResult:
        cfg = config or DiscoveryConfig()
        cancel_event = cancel_event or threading.Event()
        interface = self.transport.interface
        started = utc_now()
        xid = new_xid()
        request_hex = ""

        if not self.transport.is_capturing:
            raise CaptureNotStarted(
                "Passive capture is not running. Start capture on the selected interface first."
            )
        if not interface.mac:
            raise TransportError("Selected interface has no MAC address")
        if not 0.5 <= float(cfg.timeout_s) <= 60.0:
            raise TransportError("Discovery timeout must be 0.5..60 seconds")
        if not 1 <= int(cfg.response_delay_factor) <= 6400:
            raise TransportError("ResponseDelayFactor must be 1..6400")
        if cfg.identify_filter_name is not None:
            report = validate_station_name(cfg.identify_filter_name)
            if not cfg.identify_filter_name or not report.ok:
                raise TransportError(
                    "Invalid Identify filter NameOfStation: "
                    + (
                        report.summary()
                        if cfg.identify_filter_name
                        else "must not be empty"
                    )
                )

        if progress:
            progress(f"Waiting for request pacing ({self.limiter.remaining_s():.1f} s)…")
        if not self.limiter.wait(cancel_event):
            finished = utc_now()
            return DiscoveryResult(
                interface_id=interface.id,
                xid=xid,
                started_at=started,
                finished_at=finished,
                timeout_s=cfg.timeout_s,
                response_delay_factor=cfg.response_delay_factor,
                vlan_id=cfg.vlan_id,
                cancelled=True,
                warnings=["Cancelled before the request was transmitted"],
            )

        try:
            request = build_identify_request(
                interface.mac,
                xid,
                dst_mac=cfg.unicast_mac or DCP_MULTICAST_MAC,
                response_delay_factor=cfg.response_delay_factor,
                vlan_id=cfg.vlan_id,
                name_of_station=cfg.identify_filter_name,
            )
            request_hex = request.hex()
        except Exception as exc:
            raise TransportError(f"Could not encode Identify request: {exc}") from exc

        now_mono = time.monotonic()
        pending = _Pending(
            xid=xid,
            deadline_monotonic=now_mono + float(cfg.timeout_s),
            request_monotonic=now_mono,
            request_tx_utc=utc_now(),
            target_mac=cfg.unicast_mac,
        )
        with self._lock:
            if self._pending is not None:
                raise TransportError("Another discovery transaction is already pending")
            self._pending = pending

        try:
            self.transport.send_frame(request)
        except Exception as exc:
            with self._lock:
                self._pending = None
            finished = utc_now()
            message = str(exc) if isinstance(exc, TransportError) else f"Transmission failed: {exc}"
            return DiscoveryResult(
                interface_id=interface.id,
                xid=xid,
                started_at=started,
                finished_at=finished,
                timeout_s=cfg.timeout_s,
                response_delay_factor=cfg.response_delay_factor,
                vlan_id=cfg.vlan_id,
                request_frame_hex=request_hex,
                error=message,
                warnings=["No frame is reported as transmitted"],
            )

        self.limiter.note_sent()
        with self._lock:
            self._record(
                pending,
                timestamp=pending.request_tx_utc,
                event="identify_request",
                interface_id=interface.id,
                outcome=TransactionOutcome.TRANSMITTED,
                detail=(
                    f"Identify {'unicast to ' + cfg.unicast_mac if cfg.unicast_mac else 'multicast'}"
                    + (
                        f", NameOfStation filter {cfg.identify_filter_name!r}"
                        if cfg.identify_filter_name
                        else ""
                    )
                    + f"; timeout {cfg.timeout_s:.1f} s, response delay factor "
                    f"{cfg.response_delay_factor}"
                ),
                xid=xid,
                service="Identify",
                peer_mac=cfg.unicast_mac,
                frame_id=0xFEFE,
                raw_hex=request_hex,
            )
        self._log(
            "discovery.request_transmitted",
            f"Identify request transmitted (Xid 0x{xid:08x})",
            {
                "xid": xid,
                "interface": interface.id,
                "frame_hex": request_hex,
                "identify_filter_name": cfg.identify_filter_name,
            },
        )

        collect_until_deadline(
            pending,
            cancel_event,
            grace_s=LATE_RESPONSE_GRACE_S,
            progress=progress,
            progress_text=lambda remaining: f"Listening… {remaining:.1f} s remaining",
        )

        cancelled = cancel_event.is_set()
        with self._lock:
            self._pending = None
            devices = list(pending.devices.values())
            transactions = pending.ordered_transactions()
            duplicate_responses = pending.duplicate_responses
            unmatched = pending.unmatched_responses
            late = pending.late_responses

        finished = utc_now()
        warnings: list[str] = []
        in_window = [d for d in devices if not any("after the configured timeout" in w for w in d.warnings)]
        if not in_window:
            warnings.append(
                "No matching response was observed. This does not prove that no device exists "
                "on the segment; check interface, VLAN, switch multicast handling, privileges, "
                "and timeout/ResponseDelayFactor."
            )
            if cfg.identify_filter_name:
                warnings.append(
                    "A NameOfStation filter was applied; only devices advertising exactly "
                    f"{cfg.identify_filter_name!r} respond. The match is exact, including case."
                )
            transactions.append(
                TransactionRecord(
                    timestamp=finished,
                    event="identify_timeout",
                    interface_id=interface.id,
                    outcome=TransactionOutcome.OUTCOME_UNKNOWN,
                    detail="No matching Identify response within the configured window",
                    xid=xid,
                    service="Identify",
                    frame_id=0xFEFE,
                )
            )
        max_spread_ms = max(0, (int(cfg.response_delay_factor) - 1) * 10)
        if cfg.timeout_s * 1000 < max_spread_ms:
            warnings.append(
                f"Timeout ({cfg.timeout_s * 1000:.0f} ms) is shorter than the maximum "
                f"response spread implied by ResponseDelayFactor ({max_spread_ms} ms)."
            )
        if cancelled:
            warnings.append("Discovery was cancelled; results are partial.")
        if late:
            warnings.append(f"{late} response(s) arrived after the timeout window.")
        if unmatched:
            warnings.append(f"{unmatched} unrelated response(s) were ignored (Xid/target mismatch).")

        result = DiscoveryResult(
            interface_id=interface.id,
            xid=xid,
            started_at=started,
            finished_at=finished,
            timeout_s=cfg.timeout_s,
            response_delay_factor=cfg.response_delay_factor,
            vlan_id=cfg.vlan_id,
            devices=devices,
            transactions=transactions,
            request_frame_hex=request_hex,
            request_count=1,
            duplicate_responses=duplicate_responses,
            unmatched_responses=unmatched,
            late_responses=late,
            cancelled=cancelled,
            identify_filter_name=cfg.identify_filter_name,
            warnings=warnings,
        )
        self._log(
            "discovery.finished",
            result.outcome_text,
            {
                "xid": xid,
                "interface": interface.id,
                "duration_ms": round(result.duration_ms, 3),
                "devices": [d.mac for d in devices],
                "started": iso_utc(started),
                "finished": iso_utc(finished),
            },
        )
        return result
