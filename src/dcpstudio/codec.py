"""Pure DCP frame construction and defensive parsing.

No socket, GUI, or Scapy I/O lives here. This module is byte-oriented and fully
unit-testable. It contains the verified request builders for Identify, Get and
the guarded Set/Reset operations. State-changing services are responsible for
the configuration-mode gate, per-operation confirmation, target revalidation and
post-action checks; this module only encodes bytes.

Wire layout verified against p-net ``pf_dcp.c`` / ``pf_cmina.c`` and the
Wireshark ``pn_dcp`` dissector; see ``docs/references.md``.
"""

from __future__ import annotations

import ipaddress
import secrets
import struct
from collections.abc import Iterable, Sequence
from datetime import datetime

from .constants import (
    BLOCK_QUALIFIER_PERMANENT,
    BLOCK_QUALIFIER_TEMPORARY,
    DCP_FRAME_IDS,
    DCP_HEADER_SIZE,
    DCP_MULTICAST_MAC,
    DEFAULT_RESPONSE_DELAY_FACTOR,
    ETHERNET_MIN_FRAME_BYTES,
    ETHERTYPE_PROFINET,
    ETHERTYPE_QINQ,
    ETHERTYPE_VLAN,
    LEGACY_FACTORY_RESET_QUALIFIER,
    MAX_RESPONSE_DELAY_FACTOR,
    MIN_RESPONSE_DELAY_FACTOR,
    SIGNAL_VALUE_FLASH_ONCE,
    SUBOPTION_NAMES,
    SUPPORTED_RESET_MODES,
    AllSubOption,
    ControlSubOption,
    DeviceSubOption,
    FrameId,
    IpSubOption,
    Option,
    ServiceId,
    ServiceType,
)
from .model import DcpBlock, DcpFrame, DeviceIdentity, mac_to_str, utc_now
from .outcomes import ResponseVerdict

_MAC_RE_BYTES = 6


class DcpEncodingError(ValueError):
    """Raised when a caller supplies invalid parameters for frame encoding."""


def new_xid() -> int:
    """Return a random non-zero 32-bit transaction identifier."""
    value = secrets.randbits(32)
    return value or 1


def parse_mac(value: str) -> bytes:
    parts = value.strip().replace("-", ":").split(":")
    if len(parts) != 6:
        raise DcpEncodingError(f"Invalid MAC address: {value!r}")
    try:
        raw = bytes(int(p, 16) for p in parts)
    except ValueError as exc:
        raise DcpEncodingError(f"Invalid MAC address: {value!r}") from exc
    if any(len(p) not in (1, 2) for p in parts):
        raise DcpEncodingError(f"Invalid MAC address: {value!r}")
    return raw


def _u16(value: int) -> bytes:
    return struct.pack("!H", value & 0xFFFF)


def _u32(value: int) -> bytes:
    return struct.pack("!I", value & 0xFFFFFFFF)


def _read_u16(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return struct.unpack_from("!H", data, offset)[0]


def _require_unicast(value: str) -> bytes:
    raw = parse_mac(value)
    if raw[0] & 1:
        raise DcpEncodingError(
            "State-changing DCP requests must target exactly one unicast device MAC"
        )
    return raw


def request_qualifier(
    kind: str,
    *,
    permanent: bool = True,
    reset_mode: int | None = None,
) -> int:
    """Wire BlockQualifier for one guarded Set/Reset operation.

    Single source of truth for both the encoders and the operator-facing
    display, so a confirmation dialog cannot show a different qualifier than
    the one that is transmitted. ``kind`` matches ``WriteRequest.kind``:
    ``set_name`` / ``set_ip`` / ``reset`` / ``reset_legacy``.
    """
    if kind == "reset":
        return int(reset_mode or 0) << 1
    if kind == "reset_legacy":
        return LEGACY_FACTORY_RESET_QUALIFIER
    if kind in ("set_name", "set_ip"):
        return BLOCK_QUALIFIER_PERMANENT if permanent else BLOCK_QUALIFIER_TEMPORARY
    raise DcpEncodingError(f"Unsupported write operation {kind!r}")


def pad_to_min_frame(frame: bytes) -> bytes:
    """Zero-pad an Ethernet frame to the 60-byte wire minimum (FCS excluded).

    DCP requests are shorter than the minimum, so the transport pads them
    before transmission. Padding is not part of the DCP PDU and is therefore
    applied at the wire layer, not by the request builders.
    """
    if len(frame) >= ETHERNET_MIN_FRAME_BYTES:
        return frame
    return frame + b"\x00" * (ETHERNET_MIN_FRAME_BYTES - len(frame))


def _ether_header(
    dst_mac: bytes,
    src_mac: bytes,
    *,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
) -> bytes:
    if len(dst_mac) != _MAC_RE_BYTES or len(src_mac) != _MAC_RE_BYTES:
        raise DcpEncodingError("MAC addresses must be 6 bytes")
    header = dst_mac + src_mac
    if vlan_id is None:
        return header + _u16(ETHERTYPE_PROFINET)
    if not 1 <= int(vlan_id) <= 4094:
        raise DcpEncodingError("VLAN ID must be in the range 1..4094")
    if not 0 <= int(vlan_priority) <= 7:
        raise DcpEncodingError("VLAN priority must be in the range 0..7")
    tci = ((int(vlan_priority) & 0x7) << 13) | (int(vlan_id) & 0x0FFF)
    return header + _u16(ETHERTYPE_VLAN) + _u16(tci) + _u16(ETHERTYPE_PROFINET)


def _dcp_header(
    service_id: int,
    service_type: int,
    xid: int,
    payload_length: int,
    *,
    response_delay_factor: int = 0,
) -> bytes:
    if not 0 <= payload_length <= 0xFFFF:
        raise DcpEncodingError("DCP payload is too large")
    return (
        bytes([service_id & 0xFF, service_type & 0xFF])
        + _u32(xid)
        + _u16(response_delay_factor)
        + _u16(payload_length)
    )


def encode_block(
    option: int,
    suboption: int,
    *,
    value: bytes = b"",
    block_info: int | None = None,
    block_qualifier: int | None = None,
) -> bytes:
    """Encode one DCP block.

    BlockLength counts the BlockInfo/BlockQualifier and the value, but not the
    trailing alignment padding. Exactly one of block_info/block_qualifier may
    be supplied.
    """
    if block_info is not None and block_qualifier is not None:
        raise DcpEncodingError("A block carries either BlockInfo or BlockQualifier, not both")
    extra = b""
    if block_info is not None:
        extra = _u16(block_info)
    elif block_qualifier is not None:
        extra = _u16(block_qualifier)
    block_length = len(extra) + len(value)
    encoded = bytes([option & 0xFF, suboption & 0xFF]) + _u16(block_length) + extra + value
    if len(encoded) & 1:
        encoded += b"\x00"
    return encoded


def _encode_identify_name_filter(name_of_station: str) -> bytes:
    """Encode the NameOfStation block of an Identify-filter request.

    Verified against p-net ``pf_dcp_identify_req()``: the block is option
    ``02`` / sub-option ``02`` with ``BlockLength == len(name)`` and the ASCII
    name as the value. Unlike a Set block, an Identify filter block has no
    BlockInfo or BlockQualifier.
    """
    from .validation import validate_station_name

    if not name_of_station:
        raise DcpEncodingError(
            "An Identify NameOfStation filter must not be empty; use Identify-All "
            "to discover every device"
        )
    report = validate_station_name(name_of_station)
    if not report.ok:
        raise DcpEncodingError(
            "Invalid Identify filter NameOfStation: " + "; ".join(report.errors)
        )
    try:
        value = name_of_station.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DcpEncodingError("Identify filter NameOfStation must be ASCII") from exc
    return encode_block(
        int(Option.DEVICE_PROPERTIES),
        int(DeviceSubOption.NAME_OF_STATION),
        value=value,
    )


def build_identify_request(
    src_mac: str,
    xid: int,
    *,
    dst_mac: str = DCP_MULTICAST_MAC,
    response_delay_factor: int = DEFAULT_RESPONSE_DELAY_FACTOR,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
    name_of_station: str | None = None,
) -> bytes:
    """Build a DCP Identify request, either Identify-All or a name filter.

    With ``name_of_station=None`` the PDU carries a single ``FF/FF`` (All/All)
    block with **BlockLength 0** and therefore ``DCPDataLength == 4``. Real
    hardware and the Nmap ``multicast-profinet-discovery.nse`` script use
    exactly ``ff ff 00 00``; some IO devices ignore a request
    that adds a spurious two-byte BlockQualifier.

    With a name, the PDU carries one ``02/02`` NameOfStation filter block whose
    value is the exact ASCII name (no BlockInfo/BlockQualifier). Devices only
    answer if their NameOfStation matches exactly.

    The frame is zero-padded to the 60-byte Ethernet minimum. Passing a device
    MAC yields a unicast Identify, which uses the same PDU.
    """
    if not (
        MIN_RESPONSE_DELAY_FACTOR <= int(response_delay_factor) <= MAX_RESPONSE_DELAY_FACTOR
    ):
        raise DcpEncodingError(
            f"ResponseDelayFactor must be {MIN_RESPONSE_DELAY_FACTOR}.."
            f"{MAX_RESPONSE_DELAY_FACTOR}"
        )
    payload = (
        encode_block(int(Option.ALL), int(AllSubOption.ALL))
        if name_of_station is None
        else _encode_identify_name_filter(name_of_station)
    )
    return (
        _ether_header(
            parse_mac(dst_mac),
            parse_mac(src_mac),
            vlan_id=vlan_id,
            vlan_priority=vlan_priority,
        )
        + _u16(int(FrameId.IDENTIFY_REQUEST))
        + _dcp_header(
            int(ServiceId.IDENTIFY),
            int(ServiceType.REQUEST),
            xid,
            len(payload),
            response_delay_factor=response_delay_factor,
        )
        + payload
    )


def build_get_request(
    src_mac: str,
    dst_mac: str,
    xid: int,
    selectors: Sequence[tuple[int, int]],
    *,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
) -> bytes:
    """Build a DCP Get request.

    A Get request carries a list of Option/SubOption pairs only; it has no
    BlockLength or BlockQualifier per selector. This was verified in p-net's
    ``pf_dcp_get_set`` GET branch and in Wireshark's Get selector dissection.
    """
    if not selectors:
        raise DcpEncodingError("At least one (option, sub-option) selector is required")
    payload = b"".join(bytes([int(o) & 0xFF, int(s) & 0xFF]) for o, s in selectors)
    return (
        _ether_header(
            parse_mac(dst_mac),
            parse_mac(src_mac),
            vlan_id=vlan_id,
            vlan_priority=vlan_priority,
        )
        + _u16(int(FrameId.GET_SET))
        + _dcp_header(int(ServiceId.GET), int(ServiceType.REQUEST), xid, len(payload))
        + payload
    )


def _build_set_request(
    src_mac: str,
    dst_mac: str,
    xid: int,
    block: bytes,
    *,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
) -> bytes:
    """Wrap one verified Set block in an Ethernet/DCP Set request.

    A single Set block does not require a Control/Start-Transaction or
    Control/End-Transaction sequence; p-net processes each Set block directly.
    """
    return (
        _ether_header(
            _require_unicast(dst_mac),
            parse_mac(src_mac),
            vlan_id=vlan_id,
            vlan_priority=vlan_priority,
        )
        + _u16(int(FrameId.GET_SET))
        + _dcp_header(int(ServiceId.SET), int(ServiceType.REQUEST), xid, len(block))
        + block
    )


def build_set_name_request(
    src_mac: str,
    dst_mac: str,
    xid: int,
    name: str,
    *,
    permanent: bool,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
) -> bytes:
    """Build a Set NameOfStation request (option 02 / sub-option 02).

    p-net validates ``value_length < 241`` and applies the value as an ASCII
    VisibleString without a terminating NUL. The BlockQualifier selects
    temporary (0x0000) or permanent (0x0001) storage.
    """
    from .validation import validate_station_name

    report = validate_station_name(name)
    if not report.ok:
        raise DcpEncodingError("Invalid NameOfStation: " + "; ".join(report.errors))
    try:
        value = name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DcpEncodingError("NameOfStation must be ASCII") from exc
    block = encode_block(
        int(Option.DEVICE_PROPERTIES),
        int(DeviceSubOption.NAME_OF_STATION),
        block_qualifier=(
            BLOCK_QUALIFIER_PERMANENT if permanent else BLOCK_QUALIFIER_TEMPORARY
        ),
        value=value,
    )
    return _build_set_request(
        src_mac,
        dst_mac,
        xid,
        block,
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )


def build_set_ip_request(
    src_mac: str,
    dst_mac: str,
    xid: int,
    ip_address: str,
    subnet_mask: str,
    gateway: str,
    *,
    permanent: bool,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
) -> bytes:
    """Build a Set IP parameter request (option 01 / sub-option 02).

    The value is exactly 12 bytes: IPv4 address, subnet mask and gateway in
    network byte order. p-net requires exactly ``sizeof(pf_ip_suite_t)`` bytes
    and sends a Control/Response block error 0x03 for an invalid suite.
    """
    from .validation import validate_ip_suite

    report = validate_ip_suite(ip_address, subnet_mask, gateway)
    if not report.ok:
        raise DcpEncodingError("Invalid IPv4 suite: " + "; ".join(report.errors))
    try:
        value = (
            ipaddress.IPv4Address(ip_address).packed
            + ipaddress.IPv4Address(subnet_mask).packed
            + ipaddress.IPv4Address(gateway or "0.0.0.0").packed
        )
    except ipaddress.AddressValueError as exc:
        raise DcpEncodingError(f"Invalid IPv4 parameter: {exc}") from exc
    if len(value) != 12:
        raise DcpEncodingError("IP parameter value must be exactly 12 bytes")
    block = encode_block(
        int(Option.IP),
        int(IpSubOption.IP_PARAMETER),
        block_qualifier=(
            BLOCK_QUALIFIER_PERMANENT if permanent else BLOCK_QUALIFIER_TEMPORARY
        ),
        value=value,
    )
    return _build_set_request(
        src_mac,
        dst_mac,
        xid,
        block,
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )


def build_reset_to_factory_request(
    src_mac: str,
    dst_mac: str,
    xid: int,
    reset_mode: int,
    *,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
) -> bytes:
    """Build a ResetToFactorySettings request (option 05 / sub-option 06).

    The wire BlockQualifier is ``reset_mode << 1``. Every mode defined by the
    Wireshark/IEC 61158-6-10 table is accepted (1, 2, 3, 4, 8, 9); the erased
    scope is vendor-specific and is stated in the confirmation text.
    """
    mode = int(reset_mode)
    if mode not in SUPPORTED_RESET_MODES:
        raise DcpEncodingError(
            f"Reset mode {mode} is not implemented; supported modes are "
            + ", ".join(str(m) for m in sorted(SUPPORTED_RESET_MODES))
        )
    block = encode_block(
        int(Option.CONTROL),
        int(ControlSubOption.RESET_TO_FACTORY),
        block_qualifier=mode << 1,
    )
    return _build_set_request(
        src_mac,
        dst_mac,
        xid,
        block,
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )


def build_factory_reset_legacy_request(
    src_mac: str,
    dst_mac: str,
    xid: int,
    *,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
) -> bytes:
    """Build a legacy FactoryReset request (option 05 / sub-option 05).

    Verified layout (Wireshark ``pn_dcp`` dissector, IEC 61158-6-10 section
    4.3): sub-option ``05`` with a 2-byte BlockQualifier, where ``0x0000`` is
    displayed as "Default" and every other value as "reserved". p-net accepts
    the same block as a full reset and ignores the qualifier: it sets reset
    mode 99 ("reset all"), so both application and communication parameters
    are reset (PROFINET 2.4 CMINA state table, cases 15/30).

    There is no mode field, so the erased scope cannot be selected. This build
    always transmits BlockQualifier ``0x0000``.
    """
    block = encode_block(
        int(Option.CONTROL),
        int(ControlSubOption.FACTORY_RESET_LEGACY),
        block_qualifier=LEGACY_FACTORY_RESET_QUALIFIER,
    )
    return _build_set_request(
        src_mac,
        dst_mac,
        xid,
        block,
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )


def build_signal_request(
    src_mac: str,
    dst_mac: str,
    xid: int,
    *,
    signal_value: int = SIGNAL_VALUE_FLASH_ONCE,
    vlan_id: int | None = None,
    vlan_priority: int = 0,
) -> bytes:
    """Build a Control/Signal request (option 05 / sub-option 03).

    Verified layout (Wireshark ``pn_dcp``, IEC 61158-6-10 section 4.3): a
    2-byte BlockQualifier (``0x0000``, not interpreted by Wireshark) followed by
    a 2-byte SignalValue, so ``BlockLength`` is 4. ``0x0100`` ("Flash Once") is
    the only value either reference defines and the only one transmitted here.

    p-net ignores qualifier and value and simply flashes the LED for 3 s, so the
    same block is accepted by p-net-based devices. Signal changes no stored
    configuration and does not interrupt communication.
    """
    value = int(signal_value)
    if value != SIGNAL_VALUE_FLASH_ONCE:
        raise DcpEncodingError(
            f"SignalValue 0x{value:04x} is not verified; only "
            f"0x{SIGNAL_VALUE_FLASH_ONCE:04x} (flash once) is transmitted"
        )
    block = encode_block(
        int(Option.CONTROL),
        int(ControlSubOption.SIGNAL),
        value=_u16(value),
        block_qualifier=0x0000,
    )
    return _build_set_request(
        src_mac,
        dst_mac,
        xid,
        block,
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_frame(
    raw: bytes,
    *,
    captured_at: datetime | None = None,
    interface_id: str = "",
    direction: str = "rx",
) -> DcpFrame:
    """Parse an Ethernet frame defensively. Never raises on malformed input."""
    frame = DcpFrame(
        raw=raw,
        captured_at=captured_at or utc_now(),
        interface_id=interface_id,
        direction=direction,
    )
    if len(raw) < 14:
        frame.kind = "truncated"
        frame.warnings.append(f"Frame shorter than Ethernet header ({len(raw)} bytes)")
        return frame

    frame.dst_mac = mac_to_str(raw[0:6])
    frame.src_mac = mac_to_str(raw[6:12])
    frame.ethertype = struct.unpack_from("!H", raw, 12)[0]
    offset = 14

    if frame.ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        if len(raw) < offset + 4:
            frame.kind = "truncated"
            frame.warnings.append("VLAN tag is truncated")
            return frame
        tci, inner = struct.unpack_from("!HH", raw, offset)
        frame.vlan_priority = (tci >> 13) & 0x7
        frame.vlan_id = tci & 0x0FFF
        frame.ethertype = inner
        offset += 4
        if inner in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
            frame.warnings.append("Stacked VLAN tags are not decoded beyond the first tag")

    if frame.ethertype != ETHERTYPE_PROFINET:
        frame.kind = "other"
        return frame

    if len(raw) < offset + 2:
        frame.kind = "truncated"
        frame.warnings.append("PROFINET frame has no FrameID")
        return frame

    frame.frame_id = struct.unpack_from("!H", raw, offset)[0]
    offset += 2

    if frame.frame_id not in DCP_FRAME_IDS:
        # EtherType 0x8892 also carries PROFINET RT, PTCP, alarms, etc.
        frame.kind = "profinet_other"
        return frame

    frame.kind = "dcp"
    if len(raw) < offset + DCP_HEADER_SIZE:
        frame.warnings.append(
            f"DCP header truncated: need {DCP_HEADER_SIZE} bytes, have {len(raw) - offset}"
        )
        frame.kind = "truncated"
        return frame

    # 10-byte header: u8 ServiceID, u8 ServiceType, u32 Xid, u16 delay,
    # u16 DCPDataLength. Parse each field explicitly for clarity.
    frame.service_id = raw[offset]
    frame.service_type = raw[offset + 1]
    frame.xid = struct.unpack_from("!I", raw, offset + 2)[0]
    frame.response_delay_factor = struct.unpack_from("!H", raw, offset + 6)[0]
    frame.data_length = struct.unpack_from("!H", raw, offset + 8)[0]
    offset += DCP_HEADER_SIZE

    declared = int(frame.data_length)
    frame.declared_payload_length = declared
    available = len(raw) - offset
    if declared > available:
        frame.warnings.append(
            f"DCPDataLength declares {declared} bytes but only {available} are present"
        )
        payload = raw[offset:]
    else:
        payload = raw[offset : offset + declared]
        trailing = raw[offset + declared :]
        if trailing and any(trailing):
            # All-zero trailing bytes are normal Ethernet padding; anything
            # else is unexpected extra data.
            frame.warnings.append(
                f"{len(trailing)} trailing byte(s) after declared DCP payload"
            )

    if frame.service_id not in {int(v) for v in ServiceId}:
        frame.warnings.append(f"Unknown DCP ServiceID 0x{frame.service_id:02x}")
    if frame.service_type not in {int(v) for v in ServiceType}:
        frame.warnings.append(f"Unknown DCP ServiceType 0x{frame.service_type:02x}")

    frame.blocks = _parse_blocks(payload, frame.service_id, frame.service_type, frame)
    return frame


def _parse_blocks(
    payload: bytes,
    service_id: int | None,
    service_type: int | None,
    frame: DcpFrame,
) -> list[DcpBlock]:
    blocks: list[DcpBlock] = []
    if not payload:
        return blocks

    # DCP Get request: a sequence of Option/SubOption pairs, no length fields.
    if service_id == int(ServiceId.GET) and service_type == int(ServiceType.REQUEST):
        offset = 0
        while offset + 2 <= len(payload):
            option, suboption = payload[offset], payload[offset + 1]
            blocks.append(
                DcpBlock(
                    option=option,
                    suboption=suboption,
                    block_length=0,
                    offset=offset,
                    value=b"",
                    unknown=(option, suboption) not in SUBOPTION_NAMES,
                )
            )
            offset += 2
            if len(blocks) > 512:
                frame.warnings.append("Block count exceeds safety limit; parsing stopped")
                break
        if offset != len(payload):
            frame.warnings.append(f"{len(payload) - offset} byte(s) left over in Get request")
        return blocks

    offset = 0
    while offset < len(payload):
        if len(blocks) >= 512:
            frame.warnings.append("Block count exceeds safety limit; parsing stopped")
            break
        if offset + 4 > len(payload):
            frame.warnings.append(
                f"Truncated block header at payload offset {offset} "
                f"({len(payload) - offset} byte(s) available)"
            )
            break

        option = payload[offset]
        suboption = payload[offset + 1]
        block_length = struct.unpack_from("!H", payload, offset + 2)[0]
        value_start = offset + 4
        value_end = value_start + block_length
        truncated = False
        if value_end > len(payload):
            frame.warnings.append(
                f"Block 0x{option:02x}/0x{suboption:02x} declares {block_length} bytes "
                f"but only {len(payload) - value_start} remain"
            )
            value_end = len(payload)
            truncated = True

        raw_value = payload[value_start:value_end]
        block = DcpBlock(
            option=option,
            suboption=suboption,
            block_length=block_length,
            offset=offset,
            value=raw_value,
            truncated=truncated,
            unknown=(option, suboption) not in SUBOPTION_NAMES,
        )

        is_control_response = (
            option == int(Option.CONTROL)
            and suboption == int(ControlSubOption.RESPONSE)
        )
        is_response = service_type in (
            int(ServiceType.RESPONSE_SUCCESS),
            int(ServiceType.RESPONSE_NOT_SUPPORTED),
        )
        has_block_info = is_response and not is_control_response
        has_block_info = has_block_info or (
            service_id == int(ServiceId.HELLO) and service_type == int(ServiceType.REQUEST)
        )
        # Set requests carry a BlockQualifier. Identify requests normally carry
        # filter values (for example the NameOfStation filter 02/02), not a
        # qualifier; only the legacy/tolerant All-selector form with a 2-byte
        # field is interpreted as a qualifier. Responses and Hello requests
        # carry a BlockInfo instead.
        has_qualifier = (
            service_type == int(ServiceType.REQUEST)
            and block_length > 0
            and (
                service_id == int(ServiceId.SET)
                or (
                    service_id == int(ServiceId.IDENTIFY)
                    and option == int(Option.ALL)
                    and suboption == int(AllSubOption.ALL)
                )
            )
        )

        if is_control_response:
            # Control/Response value = [involved option, involved sub-option,
            # block error]. No BlockInfo in this block.
            if len(raw_value) >= 3:
                block.error_option = raw_value[0]
                block.error_suboption = raw_value[1]
                block.block_error = raw_value[2]
            else:
                block.truncated = True
                frame.warnings.append(
                    "Control/Response block is shorter than the required 3-byte value"
                )
        elif has_block_info:
            if len(raw_value) >= 2:
                block.block_info = struct.unpack_from("!H", raw_value, 0)[0]
                block.value = raw_value[2:]
            else:
                block.truncated = True
                frame.warnings.append(
                    f"Block 0x{option:02x}/0x{suboption:02x} lacks its 2-byte BlockInfo"
                )
        elif has_qualifier:
            if len(raw_value) >= 2:
                block.block_qualifier = struct.unpack_from("!H", raw_value, 0)[0]
                block.value = raw_value[2:]
            else:
                block.truncated = True
                frame.warnings.append(
                    f"Block 0x{option:02x}/0x{suboption:02x} lacks its 2-byte BlockQualifier"
                )
        # Unknown service: keep the raw value whole rather than guessing.

        blocks.append(block)

        advance = 4 + block_length
        if advance & 1:
            advance += 1
        if advance <= 0:
            frame.warnings.append("Parser made no progress; stopping")
            break
        if offset + advance > len(payload):
            # Missing trailing padding is tolerable at the end of the payload.
            if offset + advance - 1 == len(payload):
                frame.warnings.append("Final block padding byte is missing")
            offset = len(payload)
            break
        if advance != 4 + block_length:
            pad_index = value_end
            if pad_index < len(payload) and payload[pad_index] != 0:
                block.warnings = block.warnings + ("Non-zero block padding",)
                frame.warnings.append(
                    f"Block 0x{option:02x}/0x{suboption:02x} has non-zero padding"
                )
        offset += advance

    return blocks


# ---------------------------------------------------------------------------
# Identity extraction
# ---------------------------------------------------------------------------


def _decode_text(value: bytes) -> str | None:
    value = value.rstrip(b"\x00")
    if not value:
        return None
    return value.decode("ascii", errors="replace")


def _ipv4_text(raw: bytes) -> str | None:
    if len(raw) < 4:
        return None
    return str(ipaddress.IPv4Address(raw[:4]))


def extract_device_identity(
    frame: DcpFrame,
    *,
    response_time_ms: float | None = None,
) -> DeviceIdentity | None:
    """Extract identity fields from an Identify or Get response.

    Returns ``None`` when the frame is not a supported DCP response or has no
    source MAC. Partial responses are supported: fields that are absent remain
    ``None`` and are merged later.
    """
    if (
        frame.kind != "dcp"
        or frame.service_id not in (int(ServiceId.IDENTIFY), int(ServiceId.GET))
        or frame.service_type
        not in (int(ServiceType.RESPONSE_SUCCESS), int(ServiceType.RESPONSE_NOT_SUPPORTED))
        or not frame.src_mac
    ):
        return None

    identity = DeviceIdentity(
        interface_id=frame.interface_id,
        mac=frame.src_mac,
        first_seen=frame.captured_at,
        last_seen=frame.captured_at,
        blocks=list(frame.blocks),
        warnings=list(frame.warnings),
        response_time_ms=response_time_ms,
        last_xid=frame.xid,
        last_response_hex=frame.raw.hex(),
        source="identify" if frame.service_id == int(ServiceId.IDENTIFY) else "get",
    )

    for block in frame.blocks:
        try:
            if block.option == int(Option.IP):
                if block.suboption == int(IpSubOption.MAC):
                    # Ethernet source is authoritative for identity, but keep
                    # the advertised MAC in blocks for inspection.
                    pass
                elif block.suboption == int(IpSubOption.IP_PARAMETER):
                    if len(block.value) >= 12:
                        # Present-but-zero is distinct from an absent block; this
                        # lets a later observation show that a name/IP was cleared.
                        identity.ip_address = _ipv4_text(block.value[0:4])
                        identity.subnet_mask = _ipv4_text(block.value[4:8])
                        identity.gateway = _ipv4_text(block.value[8:12])
                        identity.ip_block_info = block.block_info
                    else:
                        identity.warnings.append("IP parameter block is shorter than 12 bytes")
            elif block.option == int(Option.DEVICE_PROPERTIES):
                if block.suboption == int(DeviceSubOption.VENDOR):
                    identity.vendor_name = _decode_text(block.value)
                elif block.suboption == int(DeviceSubOption.NAME_OF_STATION):
                    # Empty value = name explicitly not set (p-net semantics).
                    identity.name_of_station = _decode_text(block.value) or ""
                elif block.suboption == int(DeviceSubOption.DEVICE_ID):
                    if len(block.value) >= 4:
                        identity.vendor_id = struct.unpack_from("!H", block.value, 0)[0]
                        identity.device_id = struct.unpack_from("!H", block.value, 2)[0]
                    else:
                        identity.warnings.append("Device ID block is shorter than 4 bytes")
                elif block.suboption == int(DeviceSubOption.DEVICE_ROLE):
                    if block.value:
                        identity.device_role_flags = block.value[0]
                    else:
                        identity.warnings.append("Device role block has no value")
                elif block.suboption == int(DeviceSubOption.DEVICE_OPTIONS):
                    pairs = [
                        (block.value[i], block.value[i + 1])
                        for i in range(0, len(block.value) - 1, 2)
                    ]
                    for pair in pairs:
                        if pair not in identity.device_options:
                            identity.device_options.append(pair)
                    if len(block.value) & 1:
                        identity.warnings.append("Device options block has a trailing byte")
                elif block.suboption == int(DeviceSubOption.ALIAS):
                    identity.alias = _decode_text(block.value)
                elif block.suboption == int(DeviceSubOption.DEVICE_INSTANCE):
                    if len(block.value) >= 2:
                        identity.device_instance = (block.value[0], block.value[1])
                elif block.suboption == int(DeviceSubOption.OEM_DEVICE_ID):
                    if len(block.value) >= 4:
                        identity.oem_vendor_id = struct.unpack_from("!H", block.value, 0)[0]
                        identity.oem_device_id = struct.unpack_from("!H", block.value, 2)[0]
        except (IndexError, struct.error, ValueError) as exc:  # defensive
            identity.warnings.append(
                f"Could not decode block 0x{block.option:02x}/0x{block.suboption:02x}: {exc}"
            )

    # Preserve option names/order from the advertised Device Options block.
    return identity


def find_block(frame: DcpFrame, option: int, suboption: int) -> DcpBlock | None:
    for block in frame.blocks:
        if block.option == option and block.suboption == suboption:
            return block
    return None


def identify_filter_name(frame: DcpFrame) -> str | None:
    """Return the NameOfStation filter of an Identify request, if present.

    Returns ``None`` for Identify-All, for non-request frames, and when no
    NameOfStation filter block is present.
    """
    if (
        frame.kind != "dcp"
        or frame.frame_id != int(FrameId.IDENTIFY_REQUEST)
        or frame.service_id != int(ServiceId.IDENTIFY)
        or frame.service_type != int(ServiceType.REQUEST)
    ):
        return None
    block = find_block(
        frame,
        int(Option.DEVICE_PROPERTIES),
        int(DeviceSubOption.NAME_OF_STATION),
    )
    if block is None:
        return None
    value = block.value.rstrip(b"\x00")
    if not value:
        return None
    return value.decode("ascii", errors="replace")


def classify_set_response(frame: DcpFrame) -> tuple[ResponseVerdict, int | None, str]:
    """Classify a DCP Set response without transmitting anything.

    Returns ``(verdict, block_error, text)`` where verdict is one of
    ``acknowledged``, ``rejected``, ``service_not_supported`` or ``unmatched``.
    This parser is used by offline tests and is the basis for the guarded-write
    checks.
    """
    if (
        frame.kind != "dcp"
        or frame.service_id != int(ServiceId.SET)
        or frame.service_type
        not in (int(ServiceType.RESPONSE_SUCCESS), int(ServiceType.RESPONSE_NOT_SUPPORTED))
    ):
        return ResponseVerdict.UNMATCHED, None, "Not a DCP Set response"
    if frame.service_type == int(ServiceType.RESPONSE_NOT_SUPPORTED):
        return (
            ResponseVerdict.SERVICE_NOT_SUPPORTED,
            None,
            "Device reports ServiceID Set as unsupported",
        )
    for block in frame.blocks:
        if block.option == int(Option.CONTROL) and block.suboption == int(
            ControlSubOption.RESPONSE
        ):
            error = block.block_error
            if error is None:
                return ResponseVerdict.REJECTED, None, "Malformed Control/Response block"
            if error == 0:
                return ResponseVerdict.ACKNOWLEDGED, 0, "Set acknowledged with block error 0"
            return ResponseVerdict.REJECTED, error, block.error_text or f"Block error 0x{error:02x}"
    return ResponseVerdict.REJECTED, None, "Set response contains no Control/Response block"


def blocks_summary(blocks: Iterable[DcpBlock]) -> str:
    return ", ".join(
        f"{b.option_name}/{b.suboption_name} ({len(b.value)} B)" for b in blocks
    )
