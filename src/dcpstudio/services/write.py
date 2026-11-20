"""Guarded DCP Set and Reset transactions.

Every state-changing request passes through the same sequence:

1. per-operation confirmation (``SafetyGate``);
2. a fresh read-only Identify to revalidate the selected target immediately
   before transmission (unicast first; one NameOfStation-filtered multicast
   fallback for a device that ignores unicast, MAC match required);
3. exactly one unicast Set request, with no automatic retry;
4. correlation by FrameID, ServiceID, Xid, source MAC and destination MAC;
5. for Name/IP, one independent read-back Get (no retry);
6. for reset, an optional user-triggered post-check by read-only Identify,
   polled inside a bounded window because the device may reboot.

An acknowledgement is never reported as proof that a change persisted or that a
reset completed. A timeout is reported as outcome unknown, not failure.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime

from ..codec import (
    build_factory_reset_legacy_request,
    build_reset_to_factory_request,
    build_set_ip_request,
    build_set_name_request,
    classify_set_response,
    new_xid,
    parse_frame,
    parse_mac,
    request_qualifier,
)
from ..constants import (
    DEFAULT_MIN_REQUEST_INTERVAL_S,
    DEFAULT_POST_CHECK_WINDOW_S,
    DEFAULT_RESPONSE_DELAY_FACTOR,
    SUPPORTED_RESET_MODES,
    ControlSubOption,
    DeviceSubOption,
    FrameId,
    IpSubOption,
    Option,
    ServiceId,
    ServiceType,
)
from ..model import (
    DcpFrame,
    DeviceIdentity,
    DiscoveryResult,
    TransactionRecord,
    WriteResult,
    utc_now,
)
from ..outcomes import (
    PostCheckState,
    RequestState,
    ResponseVerdict,
    TransactionOutcome,
    Verification,
)
from ..safety import ConfirmationRequest, SafetyError, SafetyGate
from ..transport.base import DcpTransport, TransportError
from ..validation import validate_ip_suite, validate_station_name
from .correlation import PendingRequest, decide_frame, wait_for_response
from .discovery import LATE_RESPONSE_GRACE_S, DiscoveryConfig, DiscoveryService
from .get import GetConfig, GetService
from .rate_limit import RequestRateLimiter

EventLog = Callable[[str, str, dict], None]


@dataclass(frozen=True, slots=True)
class WriteAuthorization:
    """Operator confirmations collected by the UI or a test harness."""

    authorization_confirmed: bool = False
    safe_maintenance_confirmed: bool = False


@dataclass(slots=True)
class WriteConfig:
    timeout_s: float = 2.0
    revalidate_timeout_s: float = 2.0
    verify_timeout_s: float = 2.0
    vlan_id: int | None = None
    min_request_interval_s: float = DEFAULT_MIN_REQUEST_INTERVAL_S
    verify_after_set: bool = True
    post_check_window_s: float = DEFAULT_POST_CHECK_WINDOW_S


@dataclass(slots=True)
class WriteRequest:
    kind: str  # set_name | set_ip | reset | reset_legacy
    target_mac: str
    confirmation: ConfirmationRequest
    authorization: WriteAuthorization
    config: WriteConfig = field(default_factory=WriteConfig)
    name: str | None = None
    ip_address: str | None = None
    subnet_mask: str | None = None
    gateway: str | None = None
    permanent: bool = True
    reset_mode: int | None = None
    # Current NameOfStation forwarded from the selected device. It is only used
    # for the read-only revalidation fallback (a filtered multicast Identify)
    # when the target ignores unicast Identify; it never reaches the Set frame.
    target_name: str | None = None


@dataclass(slots=True)
class _PendingWrite(PendingRequest):
    """A guarded Set/Reset awaiting its Control/Response."""

    expected_option: int = 0
    expected_suboption: int = 0


def identity_text(device: DeviceIdentity) -> str:
    """Stable target-identity text used for revalidation."""
    name = device.name_of_station if device.name_of_station else "<not set>"
    return (
        f"{device.mac} | {name} | {device.ip_text} | {device.vendor_device_text}"
    )


@dataclass(slots=True)
class TargetProbe:
    """One target revalidation: unicast Identify, then a filtered fallback."""

    device: DeviceIdentity | None = None
    unicast: DiscoveryResult | None = None
    fallback: DiscoveryResult | None = None
    cancelled: bool = False
    error: str | None = None
    fallback_used: bool = False
    fallback_filtered: bool = False

    @property
    def results(self) -> list[DiscoveryResult]:
        return [
            discovery
            for discovery in (self.unicast, self.fallback)
            if discovery is not None
        ]


def probe_target(
    discovery_service: DiscoveryService,
    *,
    target_mac: str,
    target_name: str | None,
    timeout_s: float,
    vlan_id: int | None = None,
    response_delay_factor: int = DEFAULT_RESPONSE_DELAY_FACTOR,
    min_request_interval_s: float = DEFAULT_MIN_REQUEST_INTERVAL_S,
    allow_unfiltered_fallback: bool = False,
    cancel_event: threading.Event | None = None,
    progress: Callable[[str], None] | None = None,
    log: EventLog | None = None,
) -> TargetProbe:
    """Identify exactly one target; fall back to a filtered multicast Identify.

    Some devices answer multicast Identify but ignore the unicast form, which
    would otherwise block every guarded write. The fallback is still a *fresh*
    read-only Identify, the response must come from the expected target MAC,
    and the caller still compares the full identity text. Nothing new is sent
    that the confirmed operation did not already require, and the write itself
    is still single-shot.
    """
    cancel_event = cancel_event or threading.Event()
    probe = TargetProbe()
    try:
        probe.unicast = discovery_service.discover(
            DiscoveryConfig(
                timeout_s=timeout_s,
                response_delay_factor=response_delay_factor,
                vlan_id=vlan_id,
                unicast_mac=target_mac,
                min_request_interval_s=min_request_interval_s,
            ),
            cancel_event=cancel_event,
        )
    except Exception as exc:
        probe.error = f"Target revalidation failed: {type(exc).__name__}: {exc}"
        return probe
    if probe.unicast.cancelled:
        probe.cancelled = True
        return probe
    probe.device = _device_by_mac(probe.unicast.devices, target_mac)
    if probe.device is not None or probe.unicast.error:
        return probe
    filtered = bool(target_name)
    if not filtered and not allow_unfiltered_fallback:
        return probe
    if progress:
        progress(
            "The target ignored the unicast Identify; retrying once with a "
            + (
                "NameOfStation-filtered multicast Identify…"
                if filtered
                else "multicast Identify…"
            )
        )
    try:
        probe.fallback = discovery_service.discover(
            DiscoveryConfig(
                timeout_s=timeout_s,
                response_delay_factor=response_delay_factor,
                vlan_id=vlan_id,
                identify_filter_name=target_name,
                min_request_interval_s=min_request_interval_s,
            ),
            cancel_event=cancel_event,
        )
    except Exception as exc:
        probe.error = f"Fallback revalidation failed: {type(exc).__name__}: {exc}"
        return probe
    if probe.fallback.cancelled:
        probe.cancelled = True
        return probe
    probe.device = _device_by_mac(probe.fallback.devices, target_mac)
    probe.fallback_used = probe.device is not None
    probe.fallback_filtered = filtered
    if probe.fallback_used and log is not None:
        try:
            log(
                "safety.revalidation_fallback",
                "Target answered only a multicast Identify; revalidated by MAC"
                + (" and NameOfStation" if filtered else ""),
                {
                    "target_mac": target_mac,
                    "identify_filter_name": target_name,
                    "xid": probe.fallback.xid,
                },
            )
        except Exception:
            pass
    return probe


def _device_by_mac(
    devices: Iterable[DeviceIdentity], mac: str
) -> DeviceIdentity | None:
    wanted = mac.strip().replace("-", ":").lower()
    for device in devices:
        if device.mac.strip().replace("-", ":").lower() == wanted:
            return device
    return None


class WriteService:
    """One-shot, guarded Set dispatcher.

    Register :meth:`process_frame` with the same frame router used by discovery
    and Get. Only one write may be pending at a time.
    """

    def __init__(
        self,
        transport: DcpTransport,
        *,
        discovery_service: DiscoveryService,
        get_service: GetService,
        safety: SafetyGate | None = None,
        limiter: RequestRateLimiter | None = None,
        event_log: EventLog | None = None,
    ) -> None:
        self.transport = transport
        self.discovery_service = discovery_service
        self.get_service = get_service
        self.safety = safety or SafetyGate()
        self.limiter = limiter or RequestRateLimiter()
        self.event_log = event_log
        self._lock = threading.Lock()
        self._pending: _PendingWrite | None = None

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

    @staticmethod
    def _record(pending: _PendingWrite, **kwargs) -> None:
        pending.transactions.append(TransactionRecord(**kwargs))

    # ------------------------------------------------------------- callbacks
    def process_frame(self, raw: bytes, timestamp: datetime, direction: str) -> None:
        if direction != "rx":
            return
        with self._lock:
            if self._pending is None:
                return

        frame = parse_frame(
            raw, captured_at=timestamp, interface_id=self.transport.interface.id
        )
        if (
            frame.kind != "dcp"
            or frame.frame_id != int(FrameId.GET_SET)
            or frame.service_id != int(ServiceId.SET)
            or frame.service_type
            not in (
                int(ServiceType.RESPONSE_SUCCESS),
                int(ServiceType.RESPONSE_NOT_SUPPORTED),
            )
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
                label="Set",
                service="Set",
                event="set_response",
                duplicate_detail="A Set response was already received for this Xid",
                extra_check=_wrong_block_detail,
            )
            if decision is not None:
                return

            pending.mark_response(frame, timestamp)
            verdict, error, text = classify_set_response(frame)
            self._record(
                pending,
                timestamp=timestamp,
                event="set_response",
                interface_id=self.transport.interface.id,
                outcome=(
                    TransactionOutcome.LATE_RESPONSE
                    if pending.late
                    else f"{TransactionOutcome.MATCHING_RESPONSE_RECEIVED}:{verdict}"
                ),
                detail=f"{verdict}: {text}",
                xid=pending.xid,
                service="Set",
                peer_mac=frame.src_mac,
                frame_id=frame.frame_id,
                rtt_ms=pending.rtt_ms,
                raw_hex=frame.raw.hex(),
            )
            pending.notify_response()

    # -------------------------------------------------------------- execute
    def execute(
        self,
        request: WriteRequest,
        *,
        cancel_event: threading.Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> WriteResult:
        cancel_event = cancel_event or threading.Event()
        xid = new_xid()
        operation_text, option, suboption = _operation_shape(request)
        result = self._new_result(request, xid=xid, operation_text=operation_text)

        if not self._preflight(request, result):
            return result
        if not self._revalidate(request, result, cancel_event, progress):
            return result

        pending = self._transmit_once(
            request,
            result,
            xid=xid,
            option=option,
            suboption=suboption,
            cancel_event=cancel_event,
            progress=progress,
        )
        if pending is None:
            return result

        response, cancelled_before_response = self._await_response(
            pending, result, cancel_event, progress
        )
        if response is None:
            return self._finish_without_response(result, request, cancelled_before_response)

        self._classify_response(result, response)
        if result.state == "acknowledged" and not cancelled_before_response:
            if request.kind in ("set_name", "set_ip"):
                self._execute_set(
                    result, request, cancel_event=cancel_event, progress=progress
                )
            else:
                self._execute_reset(result)

        result.finished_at = utc_now()
        result.transactions.sort(key=lambda record: record.timestamp)
        self._log(
            "write.finished",
            result.outcome_text,
            {
                "xid": xid,
                "kind": request.kind,
                "target": request.target_mac,
                "state": result.state,
                "verification": result.verification,
            },
        )
        return result

    # ------------------------------------------------------- execute phases
    def _new_result(
        self, request: WriteRequest, *, xid: int, operation_text: str
    ) -> WriteResult:
        cfg = request.config
        started = utc_now()
        return WriteResult(
            interface_id=self.transport.interface.id,
            xid=xid,
            target_mac=request.target_mac,
            operation=request.kind,
            operation_text=operation_text,
            parameters=dict(request.confirmation.proposed_parameters),
            started_at=started,
            finished_at=started,
            timeout_s=cfg.timeout_s,
            vlan_id=cfg.vlan_id,
            permanent=request.permanent if request.kind in ("set_name", "set_ip") else None,
            block_qualifier=_request_qualifier(request),
            reset_mode=request.reset_mode if request.kind == "reset" else None,
        )

    def _preflight(self, request: WriteRequest, result: WriteResult) -> bool:
        """Validation, confirmation and capture preconditions. No frame is sent."""
        try:
            self._validate_request(request)
            self._confirm(request)
        except (SafetyError, ValueError) as exc:
            result.state = RequestState.BLOCKED
            result.error = str(exc)
            result.finished_at = utc_now()
            result.warnings.append("No frame was transmitted.")
            self._log(
                "write.blocked",
                str(exc),
                {"target": request.target_mac, "kind": request.kind},
            )
            return False

        if not self.transport.is_capturing:
            result.state = RequestState.BLOCKED
            result.error = "Passive capture is not running"
            result.finished_at = utc_now()
            result.warnings.append("No frame was transmitted.")
            return False
        if not self.transport.interface.mac:
            result.state = RequestState.BLOCKED
            result.error = "Selected interface has no MAC address"
            result.finished_at = utc_now()
            result.warnings.append("No frame was transmitted.")
            return False
        return True

    def _revalidate(
        self,
        request: WriteRequest,
        result: WriteResult,
        cancel_event: threading.Event,
        progress: Callable[[str], None] | None,
    ) -> bool:
        """Step 1: fresh Identify revalidation immediately before Set."""
        cfg = request.config
        if progress:
            progress("Revalidating target with one read-only Identify…")
        probe = probe_target(
            self.discovery_service,
            target_mac=request.target_mac,
            target_name=request.target_name,
            timeout_s=cfg.revalidate_timeout_s,
            vlan_id=cfg.vlan_id,
            min_request_interval_s=cfg.min_request_interval_s,
            cancel_event=cancel_event,
            progress=progress,
            log=self._log,
        )
        for discovery in probe.results:
            result.transactions.extend(discovery.transactions)

        if probe.cancelled:
            result.state = RequestState.CANCELLED
            result.cancelled = True
            result.finished_at = utc_now()
            result.warnings.append(
                "Cancelled during target revalidation; no Set frame was sent."
            )
            return False

        if probe.device is None:
            result.state = RequestState.TARGET_UNVERIFIED
            if probe.error:
                result.error = probe.error
            elif request.target_name:
                result.error = (
                    "The selected target did not answer a fresh unicast Identify or a "
                    "NameOfStation-filtered multicast Identify. "
                    "No Set/Reset frame was transmitted."
                )
            else:
                result.error = (
                    "The selected target did not answer a fresh unicast Identify. "
                    "No Set/Reset frame was transmitted."
                )
            result.finished_at = utc_now()
            result.warnings.append("No state-changing frame was transmitted.")
            for discovery in probe.results:
                result.warnings.extend(discovery.warnings)
            return False

        result.before_identity = probe.device
        if probe.fallback_used:
            result.warnings.append(
                "The target ignored the unicast Identify; it was revalidated with a "
                "NameOfStation-filtered multicast Identify and the MAC matched."
            )
        try:
            self.safety.revalidate_target(
                request.confirmation,
                live_mac=probe.device.mac,
                live_identity=identity_text(probe.device),
            )
        except SafetyError as exc:
            result.state = RequestState.TARGET_UNVERIFIED
            result.error = str(exc)
            result.finished_at = utc_now()
            result.warnings.append("No state-changing frame was transmitted.")
            return False
        return True

    def _transmit_once(
        self,
        request: WriteRequest,
        result: WriteResult,
        *,
        xid: int,
        option: int,
        suboption: int,
        cancel_event: threading.Event,
        progress: Callable[[str], None] | None,
    ) -> _PendingWrite | None:
        """Step 2: encode, pace and send exactly one frame. No retry."""
        cfg = request.config
        try:
            raw_request = self._build(request, xid)
            result.request_frame_hex = raw_request.hex()
        except Exception as exc:
            result.state = RequestState.BLOCKED
            result.error = f"Could not encode the request: {exc}"
            result.finished_at = utc_now()
            result.warnings.append("No frame was transmitted.")
            return None

        if progress:
            progress(f"Waiting for request pacing ({self.limiter.remaining_s():.1f} s)…")
        if not self.limiter.wait(cancel_event):
            result.state = RequestState.CANCELLED
            result.cancelled = True
            result.finished_at = utc_now()
            result.warnings.append(
                "Cancelled before the state-changing frame was transmitted."
            )
            return None

        pending = _PendingWrite(
            xid=xid,
            target_mac=request.target_mac,
            expected_option=option,
            expected_suboption=suboption,
            deadline_monotonic=time.monotonic() + float(cfg.timeout_s),
            request_monotonic=time.monotonic(),
            request_tx_utc=utc_now(),
        )
        with self._lock:
            if self._pending is not None:
                result.state = RequestState.ERROR
                result.error = "Another state-changing transaction is already pending"
                result.finished_at = utc_now()
                return None
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
            return None

        result.transmitted = True
        self.limiter.note_sent()
        with self._lock:
            self._record(
                pending,
                timestamp=pending.request_tx_utc,
                event="set_request",
                interface_id=self.transport.interface.id,
                outcome=TransactionOutcome.TRANSMITTED,
                detail=(
                    f"{result.operation_text}; "
                    f"qualifier 0x{_request_qualifier(request):04x}; "
                    f"timeout {cfg.timeout_s:.1f} s; no retry"
                ),
                xid=xid,
                service="Set",
                peer_mac=request.target_mac,
                frame_id=int(FrameId.GET_SET),
                raw_hex=raw_request.hex(),
            )
        self._log(
            "write.request_transmitted",
            f"{result.operation_text} transmitted (Xid 0x{xid:08x})",
            {
                "xid": xid,
                "target": request.target_mac,
                "kind": request.kind,
                "request_hex": raw_request.hex(),
            },
        )
        return pending

    def _await_response(
        self,
        pending: _PendingWrite,
        result: WriteResult,
        cancel_event: threading.Event,
        progress: Callable[[str], None] | None,
    ) -> tuple[DcpFrame | None, bool]:
        """Step 3: bounded wait for the first matching response. No retry."""
        wait_for_response(
            pending,
            cancel_event,
            grace_s=LATE_RESPONSE_GRACE_S,
            progress=progress,
            progress_text=lambda remaining: (
                f"Waiting for Set response… {remaining:.1f} s remaining"
            ),
        )

        cancelled_before_response = cancel_event.is_set() and pending.response is None
        with self._lock:
            self._pending = None
            response = pending.response
            late = pending.late
            rtt_ms = pending.rtt_ms
            transactions = list(pending.transactions)
            unmatched = pending.unmatched_responses
            duplicates = pending.duplicate_responses
        result.transactions.extend(transactions)
        result.finished_at = utc_now()
        result.unmatched_responses = unmatched
        result.duplicate_responses = duplicates
        result.rtt_ms = rtt_ms
        result.late = late
        return response, cancelled_before_response

    def _finish_without_response(
        self,
        result: WriteResult,
        request: WriteRequest,
        cancelled_before_response: bool,
    ) -> WriteResult:
        if cancelled_before_response:
            result.state = RequestState.CANCELLED
            result.cancelled = True
            result.warnings.append(
                "Cancelled while waiting. The Set/Reset frame had already been transmitted; "
                "cancellation does not undo it, and the outcome is unknown. Do not assume "
                "success or failure."
            )
            result.transactions.append(
                TransactionRecord(
                    timestamp=result.finished_at,
                    event="set_cancelled",
                    interface_id=self.transport.interface.id,
                    outcome=TransactionOutcome.OUTCOME_UNKNOWN,
                    detail="Cancelled after transmission; no matching response observed",
                    xid=result.xid,
                    service="Set",
                    peer_mac=request.target_mac,
                    frame_id=int(FrameId.GET_SET),
                )
            )
        else:
            result.state = RequestState.NO_RESPONSE
            result.warnings.append(
                "No matching Set response was observed. This is outcome unknown, not "
                "proof that the device rejected or failed to apply the operation. "
                "No automatic retry was performed."
            )
            result.transactions.append(
                TransactionRecord(
                    timestamp=result.finished_at,
                    event="set_timeout",
                    interface_id=self.transport.interface.id,
                    outcome=TransactionOutcome.OUTCOME_UNKNOWN,
                    detail="No matching Set response within the configured window",
                    xid=result.xid,
                    service="Set",
                    peer_mac=request.target_mac,
                    frame_id=int(FrameId.GET_SET),
                )
            )
        result.transactions.sort(key=lambda record: record.timestamp)
        self._log("write.finished", result.outcome_text, result.to_dict())
        return result

    def _classify_response(self, result: WriteResult, response: DcpFrame) -> None:
        result.response_frame_hex = response.raw.hex()
        verdict, error, text = classify_set_response(response)
        result.response_verdict = verdict
        result.block_error = error
        if result.late:
            result.state = RequestState.LATE_RESPONSE
            result.warnings.append("The Set response arrived after the configured timeout.")
        elif verdict == ResponseVerdict.ACKNOWLEDGED:
            result.state = RequestState.ACKNOWLEDGED
        elif verdict == ResponseVerdict.REJECTED:
            result.state = RequestState.REJECTED
        elif verdict == ResponseVerdict.SERVICE_NOT_SUPPORTED:
            result.state = RequestState.SERVICE_NOT_SUPPORTED
        else:
            result.state = RequestState.ERROR
            result.error = text

    def _execute_set(
        self,
        result: WriteResult,
        request: WriteRequest,
        *,
        cancel_event: threading.Event,
        progress: Callable[[str], None] | None,
    ) -> None:
        if request.config.verify_after_set:
            self._verify_set(
                result, request, cancel_event=cancel_event, progress=progress
            )
            return
        result.verification = Verification.NOT_ATTEMPTED
        result.verification_detail = (
            "Read-back verification was disabled for this operation. "
            "The acknowledgement is not proof that the value persisted."
        )

    def _execute_reset(self, result: WriteResult) -> None:
        result.verification = Verification.NOT_ATTEMPTED
        result.verification_detail = (
            "Reset acknowledgement is not proof of completion. Use the read-only "
            "post-check when the device is reachable."
        )

    # ------------------------------------------------------------ validation
    def _validate_request(self, request: WriteRequest) -> None:
        if request.kind not in ("set_name", "set_ip", "reset", "reset_legacy"):
            raise ValueError(f"Unsupported write operation {request.kind!r}")
        if request.confirmation.interface_id != self.transport.interface.id:
            raise SafetyError("Confirmation interface does not match the active interface.")
        if request.confirmation.target_mac.strip().lower() != request.target_mac.strip().lower():
            raise SafetyError("Confirmation target does not match the selected target MAC.")
        try:
            target_raw = parse_mac(request.target_mac)
        except Exception as exc:
            raise SafetyError(f"Invalid target MAC: {exc}") from exc
        if target_raw[0] & 1:
            raise SafetyError(
                "State-changing requests must target exactly one unicast device MAC."
            )
        if request.confirmation.allows_batch or request.confirmation.allows_broadcast:
            raise SafetyError("Batch and broadcast state changes are forbidden.")
        if not 0.5 <= float(request.config.timeout_s) <= 60.0:
            raise ValueError("Set timeout must be 0.5..60 seconds")
        if not 0.5 <= float(request.config.revalidate_timeout_s) <= 60.0:
            raise ValueError("Revalidation timeout must be 0.5..60 seconds")
        if not 0.5 <= float(request.config.verify_timeout_s) <= 60.0:
            raise ValueError("Read-back timeout must be 0.5..60 seconds")
        if request.kind == "reset":
            if request.reset_mode not in SUPPORTED_RESET_MODES:
                raise ValueError(
                    "Reset mode is not implemented; supported modes are "
                    + ", ".join(str(m) for m in sorted(SUPPORTED_RESET_MODES))
                )
        elif request.kind == "reset_legacy":
            # No mode field exists; the qualifier is fixed at 0x0000 ("Default").
            if request.reset_mode is not None:
                raise ValueError("A legacy FactoryReset carries no reset mode")
        elif request.kind == "set_name":
            if request.name is None:
                raise ValueError("NameOfStation is required")
            report = validate_station_name(request.name)
            if not report.ok:
                raise ValueError("Invalid NameOfStation: " + "; ".join(report.errors))
        elif request.kind == "set_ip":
            if request.ip_address is None or request.subnet_mask is None:
                raise ValueError("IP address and subnet mask are required")
            report = validate_ip_suite(
                request.ip_address,
                request.subnet_mask,
                request.gateway or "0.0.0.0",
            )
            if not report.ok:
                raise ValueError("Invalid IPv4 suite: " + "; ".join(report.errors))

    def _confirm(self, request: WriteRequest) -> None:
        self.safety.confirm(
            request.confirmation,
            authorization_confirmed=request.authorization.authorization_confirmed,
            safe_maintenance_confirmed=request.authorization.safe_maintenance_confirmed,
        )

    def _build(self, request: WriteRequest, xid: int) -> bytes:
        src_mac = self.transport.interface.mac or ""
        if request.kind == "set_name":
            return build_set_name_request(
                src_mac,
                request.target_mac,
                xid,
                request.name or "",
                permanent=request.permanent,
                vlan_id=request.config.vlan_id,
            )
        if request.kind == "set_ip":
            return build_set_ip_request(
                src_mac,
                request.target_mac,
                xid,
                request.ip_address or "",
                request.subnet_mask or "",
                request.gateway or "0.0.0.0",
                permanent=request.permanent,
                vlan_id=request.config.vlan_id,
            )
        if request.kind == "reset":
            return build_reset_to_factory_request(
                src_mac,
                request.target_mac,
                xid,
                int(request.reset_mode or 0),
                vlan_id=request.config.vlan_id,
            )
        if request.kind == "reset_legacy":
            return build_factory_reset_legacy_request(
                src_mac,
                request.target_mac,
                xid,
                vlan_id=request.config.vlan_id,
            )
        raise ValueError(f"Unsupported write operation {request.kind!r}")

    # ------------------------------------------------------------- read-back
    def _verify_set(
        self,
        result: WriteResult,
        request: WriteRequest,
        *,
        cancel_event: threading.Event,
        progress: Callable[[str], None] | None,
    ) -> None:
        if progress:
            progress("Reading back the affected block (one read-only Get, no retry)…")
        if request.kind == "set_name":
            selector = (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.NAME_OF_STATION))
            expected = (request.name or "").encode("ascii")
        else:
            selector = (int(Option.IP), int(IpSubOption.IP_PARAMETER))
            expected = (
                ipaddress.IPv4Address(request.ip_address or "0.0.0.0").packed
                + ipaddress.IPv4Address(request.subnet_mask or "0.0.0.0").packed
                + ipaddress.IPv4Address(request.gateway or "0.0.0.0").packed
            )

        get_result = self.get_service.get(
            request.target_mac,
            GetConfig(
                timeout_s=request.config.verify_timeout_s,
                vlan_id=request.config.vlan_id,
                selectors=(selector,),
                min_request_interval_s=request.config.min_request_interval_s,
            ),
            cancel_event=cancel_event,
        )
        result.transactions.extend(get_result.transactions)
        result.warnings.extend(
            warning for warning in get_result.warnings if warning not in result.warnings
        )
        if get_result.identity is not None:
            result.after_identity = get_result.identity

        if get_result.state == RequestState.CANCELLED:
            result.verification = Verification.UNKNOWN
            result.verification_detail = "Read-back was cancelled."
            return
        if get_result.state == RequestState.SERVICE_NOT_SUPPORTED:
            result.verification = Verification.SERVICE_NOT_SUPPORTED
            result.verification_detail = "Device reports Get as unsupported."
            return
        if get_result.state != RequestState.RESPONSE_RECEIVED:
            result.verification = Verification.UNKNOWN
            result.verification_detail = (
                f"No matching read-back response ({get_result.outcome_text})."
            )
            return
        if get_result.block_errors:
            result.verification = Verification.REJECTED
            result.verification_detail = get_result.block_error_text
            return

        block = next(
            (
                item
                for item in get_result.blocks
                if (item.option, item.suboption) == selector
            ),
            None,
        )
        if block is None:
            result.verification = Verification.UNKNOWN
            result.verification_detail = "Read-back response contained no matching block."
            return
        observed = block.value.rstrip(b"\x00") if request.kind == "set_name" else block.value
        if observed == expected:
            result.verification = Verification.VERIFIED
            if request.kind == "set_name":
                result.verification_detail = f"Read-back NameOfStation={request.name!r}."
            else:
                result.verification_detail = (
                    f"Read-back {request.ip_address}/{request.subnet_mask} "
                    f"gw {request.gateway or '0.0.0.0'}."
                )
        else:
            result.verification = Verification.MISMATCH
            if request.kind == "set_name":
                result.verification_detail = (
                    "Read-back NameOfStation="
                    f"{observed.decode('ascii', errors='replace')!r}."
                )
            else:
                result.verification_detail = (
                    "Read-back IP parameter bytes="
                    f"{observed.hex()}, expected {expected.hex()}."
                )

    # ------------------------------------------------------------ post-check
    def post_check(
        self,
        result: WriteResult,
        *,
        timeout_s: float = 3.0,
        recheck_window_s: float = 0.0,
        cancel_event: threading.Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> WriteResult:
        """Read-only Identify after a reset, polled for a bounded window.

        A reset may reboot the device, so with ``recheck_window_s`` > 0 the
        read-only Identify is repeated until the device answers or the window
        expires (cancellable, still rate-limited). It proves only that the
        device answered at the same MAC; it does not prove which reset mode the
        device implemented or what data was erased, and it is never a write
        retry.
        """
        cancel_event = cancel_event or threading.Event()
        window_s = max(0.0, float(recheck_window_s))
        deadline = time.monotonic() + window_s
        attempts = 0
        probe = TargetProbe()
        while True:
            attempts += 1
            if progress:
                progress(
                    f"Post-check: read-only Identify attempt {attempts}…"
                )
            probe = probe_target(
                self.discovery_service,
                target_mac=result.target_mac,
                target_name=None,
                timeout_s=timeout_s,
                vlan_id=result.vlan_id,
                min_request_interval_s=DEFAULT_MIN_REQUEST_INTERVAL_S,
                allow_unfiltered_fallback=True,
                cancel_event=cancel_event,
                progress=progress,
                log=self._log,
            )
            for discovery in probe.results:
                result.post_check_xid = discovery.xid
                result.post_checked_at = discovery.finished_at
                result.transactions.extend(discovery.transactions)
            result.transactions.sort(key=lambda record: record.timestamp)
            if probe.cancelled:
                result.post_check_state = PostCheckState.CANCELLED
                result.post_check_detail = "Post-check was cancelled by the user."
                return result
            if probe.device is not None:
                break
            if window_s <= 0 or cancel_event.is_set() or time.monotonic() >= deadline:
                break
        if probe.device is None:
            result.post_check_state = PostCheckState.NO_RESPONSE
            prefix = (
                f"No Identify response after the reset within {window_s:.0f} s "
                f"({attempts} attempts). "
                if attempts > 1
                else "No unicast Identify response after the reset. "
            )
            result.post_check_detail = (
                prefix
                + "The device may still be rebooting; this is outcome unknown and "
                "not proof of failure."
            )
            return result
        result.post_check_state = PostCheckState.RESPONDED
        result.after_identity = probe.device
        extra = ""
        if probe.fallback_used:
            extra = (
                " The device ignored the unicast Identify; it answered a "
                + (
                    "NameOfStation-filtered multicast Identify"
                    if probe.fallback_filtered
                    else "multicast Identify"
                )
                + " for the same MAC."
            )
        elif attempts > 1:
            extra = (
                f" It responded on attempt {attempts} of the {window_s:.0f} s window."
            )
        result.post_check_detail = (
            "Device answered a read-only Identify after the reset. This proves "
            "reachability only; verify the expected name/IP scope independently."
            + extra
        )
        return result


def _wrong_block_detail(pending: _PendingWrite, frame: DcpFrame) -> str | None:
    """Return why a Control/Response belongs to another block, or ``None``.

    Control/Response carries the involved option/sub-option. If both are
    present and do not match the single block we sent, this is not our
    operation even if the Xid collides.
    """
    for block in frame.blocks:
        if (
            block.option == int(Option.CONTROL)
            and block.suboption == int(ControlSubOption.RESPONSE)
            and block.error_option is not None
            and block.error_suboption is not None
            and (
                block.error_option != pending.expected_option
                or block.error_suboption != pending.expected_suboption
            )
        ):
            return (
                "Set response refers to option/sub-option "
                f"0x{block.error_option:02x}/0x{block.error_suboption:02x}, "
                "not the requested block"
            )
    return None


def _operation_shape(request: WriteRequest) -> tuple[str, int, int]:
    if request.kind == "set_name":
        return (
            "Set NameOfStation",
            int(Option.DEVICE_PROPERTIES),
            int(DeviceSubOption.NAME_OF_STATION),
        )
    if request.kind == "set_ip":
        return "Set IP parameters", int(Option.IP), int(IpSubOption.IP_PARAMETER)
    if request.kind == "reset":
        return "ResetToFactorySettings", int(Option.CONTROL), int(ControlSubOption.RESET_TO_FACTORY)
    if request.kind == "reset_legacy":
        return (
            "Legacy FactoryReset (05/05)",
            int(Option.CONTROL),
            int(ControlSubOption.FACTORY_RESET_LEGACY),
        )
    raise ValueError(f"Unsupported write operation {request.kind!r}")


def _request_qualifier(request: WriteRequest) -> int:
    return request_qualifier(
        request.kind,
        permanent=request.permanent,
        reset_mode=request.reset_mode,
    )
