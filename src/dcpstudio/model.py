"""Immutable-ish data models shared by codec, services, reporting, and GUI."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import APP_NAME, __version__
from .constants import (
    BLOCK_ERROR_TEXT,
    DEVICE_ROLE_BITS,
    OPTION_NAMES,
    SERVICE_NAMES,
    SERVICE_TYPE_NAMES,
    SUBOPTION_NAMES,
)
from .outcomes import (
    DiscoveryOutcome,
    PostCheckState,
    RequestState,
    ResponseVerdict,
    Verification,
    discovery_outcome_text,
    get_outcome_text,
    verification_display_text,
    write_outcome_text,
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_utc(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


@dataclass(slots=True)
class DcpBlock:
    """One decoded DCP block.

    ``block_info`` is present in Identify/Get responses and Hello requests.
    ``block_qualifier`` is present in Set requests; for Identify requests it is
    only set for the legacy/tolerant All-selector form. Identify filter blocks
    carry their value directly. Control/Response blocks carry ``block_error``
    instead of block info.
    """

    option: int
    suboption: int
    block_length: int
    offset: int
    value: bytes
    block_info: int | None = None
    block_qualifier: int | None = None
    block_error: int | None = None
    error_option: int | None = None
    error_suboption: int | None = None
    truncated: bool = False
    unknown: bool = False
    warnings: tuple[str, ...] = ()

    @property
    def option_name(self) -> str:
        return OPTION_NAMES.get(self.option, f"Unknown option 0x{self.option:02x}")

    @property
    def suboption_name(self) -> str:
        return SUBOPTION_NAMES.get(
            (self.option, self.suboption),
            f"Unknown sub-option 0x{self.suboption:02x}",
        )

    @property
    def error_text(self) -> str | None:
        if self.block_error is None:
            return None
        return BLOCK_ERROR_TEXT.get(self.block_error, f"Reserved block error 0x{self.block_error:02x}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "option": self.option,
            "option_name": self.option_name,
            "suboption": self.suboption,
            "suboption_name": self.suboption_name,
            "block_length": self.block_length,
            "offset": self.offset,
            "block_info": self.block_info,
            "block_qualifier": self.block_qualifier,
            "block_error": self.block_error,
            "block_error_text": self.error_text,
            "error_option": self.error_option,
            "error_suboption": self.error_suboption,
            "value_hex": self.value.hex(),
            "value_ascii": _ascii_or_none(self.value),
            "truncated": self.truncated,
            "unknown": self.unknown,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class DcpFrame:
    """A fully parsed Ethernet frame (or a best-effort partial parse)."""

    raw: bytes
    captured_at: datetime
    interface_id: str = ""
    kind: str = "other"  # dcp | profinet_other | other | truncated
    dst_mac: str | None = None
    src_mac: str | None = None
    ethertype: int | None = None
    vlan_id: int | None = None
    vlan_priority: int | None = None
    frame_id: int | None = None
    service_id: int | None = None
    service_type: int | None = None
    xid: int | None = None
    response_delay_factor: int | None = None
    data_length: int | None = None
    declared_payload_length: int | None = None
    blocks: list[DcpBlock] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    direction: str = "rx"

    @property
    def is_dcp(self) -> bool:
        return self.kind == "dcp"

    @property
    def service_name(self) -> str:
        if self.service_id is None:
            return ""
        return SERVICE_NAMES.get(self.service_id, f"Service 0x{self.service_id:02x}")

    @property
    def service_type_name(self) -> str:
        if self.service_type is None:
            return ""
        return SERVICE_TYPE_NAMES.get(
            self.service_type, f"ServiceType 0x{self.service_type:02x}"
        )

    @property
    def is_response(self) -> bool:
        return self.service_type in (0x01, 0x05)

    def summary(self) -> str:
        if self.kind == "truncated":
            return "Truncated / unparseable frame"
        if self.kind == "other":
            return f"Non-PROFINET EtherType 0x{self.ethertype:04x}" if self.ethertype else "Non-Ethernet"
        if self.kind == "profinet_other":
            return f"PROFINET EtherType 0x8892, non-DCP FrameID 0x{self.frame_id:04x}"
        direction = "Response" if self.is_response else "Request"
        name = self.service_name or "DCP"
        return (
            f"DCP {name} {direction}, Xid 0x{(self.xid or 0):08x}, "
            f"{len(self.blocks)} block(s)"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "captured_at": iso_utc(self.captured_at),
            "interface": self.interface_id,
            "direction": self.direction,
            "kind": self.kind,
            "dst_mac": self.dst_mac,
            "src_mac": self.src_mac,
            "ethertype": self.ethertype,
            "vlan_id": self.vlan_id,
            "vlan_priority": self.vlan_priority,
            "frame_id": self.frame_id,
            "service_id": self.service_id,
            "service_name": self.service_name,
            "service_type": self.service_type,
            "service_type_name": self.service_type_name,
            "xid": self.xid,
            "response_delay_factor": self.response_delay_factor,
            "data_length": self.data_length,
            "blocks": [b.to_dict() for b in self.blocks],
            "warnings": list(self.warnings),
            "raw_hex": self.raw.hex(),
        }


@dataclass(slots=True)
class DeviceIdentity:
    """Device identity assembled from one or more Identify responses."""

    interface_id: str
    mac: str
    first_seen: datetime
    last_seen: datetime
    name_of_station: str | None = None
    ip_address: str | None = None
    subnet_mask: str | None = None
    gateway: str | None = None
    vendor_id: int | None = None
    device_id: int | None = None
    vendor_name: str | None = None
    device_role_flags: int | None = None
    device_options: list[tuple[int, int]] = field(default_factory=list)
    alias: str | None = None
    device_instance: tuple[int, int] | None = None
    oem_vendor_id: int | None = None
    oem_device_id: int | None = None
    ip_block_info: int | None = None
    blocks: list[DcpBlock] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    response_count: int = 1
    duplicate_responses: int = 0
    response_time_ms: float | None = None
    last_xid: int | None = None
    last_response_hex: str = ""
    source: str = "identify"

    @property
    def display_name(self) -> str:
        return self.name_of_station or "<not set>"

    @property
    def role_names(self) -> list[str]:
        if self.device_role_flags is None:
            return []
        return [name for bit, name in DEVICE_ROLE_BITS if self.device_role_flags & bit]

    @property
    def role_text(self) -> str:
        names = self.role_names
        if names:
            return ", ".join(names)
        if self.device_role_flags is None:
            return "not advertised"
        return f"reserved (0x{self.device_role_flags:02x})"

    @property
    def ip_text(self) -> str:
        if self.ip_address and self.ip_address != "0.0.0.0":
            return self.ip_address
        return "<not set>"

    @property
    def vendor_device_text(self) -> str:
        if self.vendor_id is None and self.device_id is None:
            return "not advertised"
        return f"0x{(self.vendor_id or 0):04x} / 0x{(self.device_id or 0):04x}"

    @property
    def options_text(self) -> str:
        if not self.device_options:
            return "not advertised"
        return ", ".join(f"0x{o:02x}/0x{s:02x}" for o, s in self.device_options)

    def merge(self, other: DeviceIdentity, *, count_as_duplicate: bool = True) -> None:
        """Merge a partial/duplicate Identify response for the same MAC."""
        self.last_seen = max(self.last_seen, other.last_seen)
        self.response_count += other.response_count
        if count_as_duplicate:
            self.duplicate_responses += 1
        else:
            self.duplicate_responses += other.duplicate_responses
        self.response_time_ms = other.response_time_ms
        self.last_xid = other.last_xid
        self.last_response_hex = other.last_response_hex
        for attr in (
            "name_of_station",
            "ip_address",
            "subnet_mask",
            "gateway",
            "vendor_id",
            "device_id",
            "vendor_name",
            "device_role_flags",
            "alias",
            "device_instance",
            "oem_vendor_id",
            "oem_device_id",
            "ip_block_info",
        ):
            value = getattr(other, attr)
            if value is not None:
                setattr(self, attr, value)
        for opt in other.device_options:
            if opt not in self.device_options:
                self.device_options.append(opt)
        seen = {(b.option, b.suboption, b.block_info): index for index, b in enumerate(self.blocks)}
        for block in other.blocks:
            key = (block.option, block.suboption, block.block_info)
            index = seen.get(key)
            if index is None:
                seen[key] = len(self.blocks)
                self.blocks.append(block)
            elif block.value or block.block_info is not None:
                # Keep the newest non-empty observation for the same block.
                self.blocks[index] = block
        for warning in other.warnings:
            if warning not in self.warnings:
                self.warnings.append(warning)

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface_id,
            "mac": self.mac,
            "name_of_station": self.name_of_station,
            "ip_address": self.ip_address,
            "subnet_mask": self.subnet_mask,
            "gateway": self.gateway,
            "vendor_id": self.vendor_id,
            "device_id": self.device_id,
            "vendor_id_hex": f"0x{self.vendor_id:04x}" if self.vendor_id is not None else None,
            "device_id_hex": f"0x{self.device_id:04x}" if self.device_id is not None else None,
            "vendor_name": self.vendor_name,
            "device_role_flags": self.device_role_flags,
            "device_role_names": self.role_names,
            "device_options": [f"0x{o:02x}/0x{s:02x}" for o, s in self.device_options],
            "alias": self.alias,
            "device_instance": list(self.device_instance) if self.device_instance else None,
            "oem_vendor_id": self.oem_vendor_id,
            "oem_device_id": self.oem_device_id,
            "ip_block_info": self.ip_block_info,
            "first_seen": iso_utc(self.first_seen),
            "last_seen": iso_utc(self.last_seen),
            "response_count": self.response_count,
            "duplicate_responses": self.duplicate_responses,
            "response_time_ms": self.response_time_ms,
            "last_xid": self.last_xid,
            "last_response_hex": self.last_response_hex,
            "source": self.source,
            "warnings": list(self.warnings),
            "blocks": [b.to_dict() for b in self.blocks],
        }


@dataclass(slots=True)
class TransactionRecord:
    timestamp: datetime
    event: str
    interface_id: str
    outcome: str
    detail: str = ""
    xid: int | None = None
    service: str = ""
    peer_mac: str | None = None
    frame_id: int | None = None
    rtt_ms: float | None = None
    raw_hex: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": iso_utc(self.timestamp),
            "event": self.event,
            "interface": self.interface_id,
            "outcome": self.outcome,
            "detail": self.detail,
            "xid": self.xid,
            "service": self.service,
            "peer_mac": self.peer_mac,
            "frame_id": self.frame_id,
            "rtt_ms": self.rtt_ms,
            "raw_hex": self.raw_hex,
        }


@dataclass(slots=True)
class DiscoveryResult:
    interface_id: str
    xid: int
    started_at: datetime
    finished_at: datetime
    timeout_s: float
    response_delay_factor: int
    vlan_id: int | None
    devices: list[DeviceIdentity] = field(default_factory=list)
    transactions: list[TransactionRecord] = field(default_factory=list)
    request_frame_hex: str = ""
    request_count: int = 1
    duplicate_responses: int = 0
    unmatched_responses: int = 0
    late_responses: int = 0
    cancelled: bool = False
    error: str | None = None
    identify_filter_name: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds() * 1000.0)

    @property
    def outcome(self) -> DiscoveryOutcome:
        if self.error:
            return DiscoveryOutcome.ERROR
        if self.cancelled:
            return DiscoveryOutcome.CANCELLED
        if not self.devices:
            return DiscoveryOutcome.NO_RESPONSES
        return DiscoveryOutcome.RESPONSES_RECEIVED

    @property
    def outcome_text(self) -> str:
        return discovery_outcome_text(self.outcome, len(self.devices))

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface_id,
            "xid": self.xid,
            "started_at": iso_utc(self.started_at),
            "finished_at": iso_utc(self.finished_at),
            "duration_ms": round(self.duration_ms, 3),
            "timeout_s": self.timeout_s,
            "response_delay_factor": self.response_delay_factor,
            "vlan_id": self.vlan_id,
            "identify_filter_name": self.identify_filter_name,
            "outcome": self.outcome,
            "request_count": self.request_count,
            "duplicate_responses": self.duplicate_responses,
            "unmatched_responses": self.unmatched_responses,
            "late_responses": self.late_responses,
            "cancelled": self.cancelled,
            "error": self.error,
            "warnings": list(self.warnings),
            "request_frame_hex": self.request_frame_hex,
            "devices": [d.to_dict() for d in self.devices],
            "transactions": [t.to_dict() for t in self.transactions],
        }


@dataclass(slots=True)
class GetResult:
    """Result of one read-only DCP Get transaction."""

    interface_id: str
    xid: int
    target_mac: str
    selectors: list[tuple[int, int]]
    started_at: datetime
    finished_at: datetime
    timeout_s: float
    vlan_id: int | None
    state: RequestState = RequestState.PENDING
    request_frame_hex: str = ""
    response_frame_hex: str = ""
    blocks: list[DcpBlock] = field(default_factory=list)
    block_errors: list[DcpBlock] = field(default_factory=list)
    identity: DeviceIdentity | None = None
    transactions: list[TransactionRecord] = field(default_factory=list)
    rtt_ms: float | None = None
    late: bool = False
    cancelled: bool = False
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds() * 1000.0)

    @property
    def outcome(self) -> RequestState:
        return self.state

    @property
    def outcome_text(self) -> str:
        return get_outcome_text(self.state)

    @property
    def block_error_text(self) -> str:
        if not self.block_errors:
            return ""
        return "; ".join(
            f"0x{(block.error_option or 0):02x}/0x{(block.error_suboption or 0):02x}: "
            f"{block.error_text or 'unknown error'}"
            for block in self.block_errors
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface_id,
            "xid": self.xid,
            "target_mac": self.target_mac,
            "selectors": [f"0x{o:02x}/0x{s:02x}" for o, s in self.selectors],
            "started_at": iso_utc(self.started_at),
            "finished_at": iso_utc(self.finished_at),
            "duration_ms": round(self.duration_ms, 3),
            "timeout_s": self.timeout_s,
            "vlan_id": self.vlan_id,
            "outcome": self.outcome,
            "state": self.state,
            "outcome_text": self.outcome_text,
            "request_frame_hex": self.request_frame_hex,
            "response_frame_hex": self.response_frame_hex,
            "blocks": [b.to_dict() for b in self.blocks],
            "block_errors": [b.to_dict() for b in self.block_errors],
            "block_error_text": self.block_error_text,
            "identity": self.identity.to_dict() if self.identity else None,
            "transactions": [t.to_dict() for t in self.transactions],
            "rtt_ms": self.rtt_ms,
            "late": self.late,
            "cancelled": self.cancelled,
            "error": self.error,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class WriteResult:
    """Result of one guarded state-changing DCP Set transaction.

    Acknowledgement and verification are deliberately separate. A device can
    acknowledge a Set yet fail to persist/apply it, and a missing response does
    not prove failure.
    """

    interface_id: str
    xid: int
    target_mac: str
    operation: str  # set_name | set_ip | reset
    operation_text: str
    parameters: dict[str, Any]
    started_at: datetime
    finished_at: datetime
    timeout_s: float
    vlan_id: int | None
    state: RequestState = RequestState.PENDING
    permanent: bool | None = None
    block_qualifier: int | None = None
    reset_mode: int | None = None
    request_frame_hex: str = ""
    response_frame_hex: str = ""
    transmitted: bool = False
    response_verdict: ResponseVerdict | None = None
    block_error: int | None = None
    before_identity: DeviceIdentity | None = None
    after_identity: DeviceIdentity | None = None
    verification: Verification = Verification.NOT_ATTEMPTED
    verification_detail: str = ""
    post_check_state: PostCheckState = PostCheckState.NOT_ATTEMPTED
    post_check_detail: str = ""
    post_checked_at: datetime | None = None
    post_check_xid: int | None = None
    transactions: list[TransactionRecord] = field(default_factory=list)
    rtt_ms: float | None = None
    late: bool = False
    cancelled: bool = False
    unmatched_responses: int = 0
    duplicate_responses: int = 0
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds() * 1000.0)

    @property
    def outcome(self) -> RequestState:
        return self.state

    @property
    def outcome_text(self) -> str:
        return write_outcome_text(self.state, self.verification, self.transmitted)

    @property
    def verification_text(self) -> str:
        return verification_display_text(self.verification, self.verification_detail)

    @property
    def block_error_text(self) -> str:
        if self.block_error is None:
            return ""
        return BLOCK_ERROR_TEXT.get(
            self.block_error, f"Reserved block error 0x{self.block_error:02x}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface_id,
            "xid": self.xid,
            "target_mac": self.target_mac,
            "operation": self.operation,
            "operation_text": self.operation_text,
            "parameters": dict(self.parameters),
            "started_at": iso_utc(self.started_at),
            "finished_at": iso_utc(self.finished_at),
            "duration_ms": round(self.duration_ms, 3),
            "timeout_s": self.timeout_s,
            "vlan_id": self.vlan_id,
            "outcome": self.outcome,
            "state": self.state,
            "outcome_text": self.outcome_text,
            "permanent": self.permanent,
            "block_qualifier": self.block_qualifier,
            "block_qualifier_hex": (
                f"0x{self.block_qualifier:04x}"
                if self.block_qualifier is not None
                else None
            ),
            "reset_mode": self.reset_mode,
            "request_frame_hex": self.request_frame_hex,
            "response_frame_hex": self.response_frame_hex,
            "transmitted": self.transmitted,
            "response_verdict": self.response_verdict,
            "block_error": self.block_error,
            "block_error_text": self.block_error_text,
            "before_identity": self.before_identity.to_dict() if self.before_identity else None,
            "after_identity": self.after_identity.to_dict() if self.after_identity else None,
            "verification": self.verification,
            "verification_text": self.verification_text,
            "post_check_state": self.post_check_state,
            "post_check_detail": self.post_check_detail,
            "post_checked_at": iso_utc(self.post_checked_at),
            "post_check_xid": self.post_check_xid,
            "transactions": [t.to_dict() for t in self.transactions],
            "rtt_ms": self.rtt_ms,
            "late": self.late,
            "cancelled": self.cancelled,
            "unmatched_responses": self.unmatched_responses,
            "duplicate_responses": self.duplicate_responses,
            "error": self.error,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class CapturedFrame:
    timestamp: datetime
    interface_id: str
    direction: str
    raw: bytes
    parsed: DcpFrame | None = None

    @property
    def summary(self) -> str:
        return self.parsed.summary() if self.parsed else "Unparsed frame"


@dataclass(slots=True)
class LogRecordData:
    timestamp: datetime
    level: str
    event: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": iso_utc(self.timestamp),
            "level": self.level,
            "event": self.event,
            "message": self.message,
            "detail": self.detail,
        }


@dataclass(slots=True)
class TestResult:
    __test__ = False

    test_id: str
    name: str
    category: str
    status: str  # passed | failed | skipped | inconclusive
    detail: str
    started_at: datetime
    duration_ms: float
    live: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "detail": self.detail,
            "started_at": iso_utc(self.started_at),
            "duration_ms": round(self.duration_ms, 3),
            "live": self.live,
            "evidence": self.evidence,
            "warnings": list(self.warnings),
        }


def _ascii_or_none(value: bytes) -> str | None:
    if not value:
        return None
    try:
        text = value.decode("ascii").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    if not text or any(ord(c) < 0x20 or ord(c) > 0x7E for c in text):
        return None
    return text


def report_metadata() -> dict[str, Any]:
    return {
        "application": APP_NAME,
        "version": __version__,
    }


def dedupe_devices(devices: Iterable[DeviceIdentity]) -> list[DeviceIdentity]:
    return list(devices)
