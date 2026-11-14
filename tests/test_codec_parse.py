from __future__ import annotations

import random
import struct

from dcpstudio.codec import (
    classify_set_response,
    extract_device_identity,
    identify_filter_name,
    parse_frame,
)
from dcpstudio.constants import ETHERTYPE_PROFINET, FrameId, ServiceId, ServiceType
from dcpstudio.fixtures import get_fixture
from dcpstudio.mock import MockNetwork, default_mock_devices


def _frame(
    *,
    src: str,
    dst: str,
    frame_id: int,
    service_id: int,
    service_type: int,
    xid: int,
    payload: bytes,
) -> bytes:
    def mac(value: str) -> bytes:
        return bytes(int(part, 16) for part in value.split(":"))

    header = (
        bytes([service_id, service_type])
        + struct.pack("!I", xid)
        + struct.pack("!H", 0)
        + struct.pack("!H", len(payload))
    )
    return mac(dst) + mac(src) + struct.pack("!H", ETHERTYPE_PROFINET) + struct.pack(
        "!H", frame_id
    ) + header + payload


def test_named_identify_response_decodes(named_response):
    frame = parse_frame(named_response, interface_id="test0")
    assert frame.kind == "dcp"
    assert frame.frame_id == FrameId.IDENTIFY_RESPONSE
    assert frame.service_id == ServiceId.IDENTIFY
    assert frame.service_type == ServiceType.RESPONSE_SUCCESS
    assert frame.xid == 0x11223344
    assert frame.warnings == []

    identity = extract_device_identity(frame, response_time_ms=1.25)
    assert identity is not None
    assert identity.mac == "02:00:00:00:00:11"
    assert identity.name_of_station == "line-01.conveyor"
    assert identity.ip_address == "192.0.2.11"
    assert identity.subnet_mask == "255.255.255.0"
    assert identity.gateway == "192.0.2.1"
    assert identity.vendor_name == "Mock Automation"
    assert identity.vendor_id == 0x002A
    assert identity.device_id == 0x0101
    assert identity.device_role_flags == 0x01
    assert identity.role_names == ["IO-Device"]
    assert (0x01, 0x02) in identity.device_options
    assert identity.ip_block_info == 0x0001
    assert identity.response_time_ms == 1.25


def test_unnamed_device_and_unset_ip(unnamed_response):
    frame = parse_frame(unnamed_response)
    identity = extract_device_identity(frame)
    assert identity is not None
    assert identity.name_of_station == ""
    assert identity.ip_address == "0.0.0.0"
    assert identity.subnet_mask == "0.0.0.0"
    assert identity.gateway == "0.0.0.0"
    assert identity.ip_text == "<not set>"
    assert identity.ip_block_info == 0x0000


def test_truncated_response_is_defensive():
    frame = parse_frame(get_fixture("identify_response_truncated"))
    assert frame.kind in ("dcp", "truncated")
    assert frame.warnings
    # Decoding may return a partial identity; it must never raise.
    extract_device_identity(frame)


def test_bad_block_length_marks_truncated():
    frame = parse_frame(get_fixture("identify_response_bad_block_length"))
    assert frame.warnings
    assert frame.blocks
    assert frame.blocks[0].truncated is True
    assert frame.blocks[0].block_length == 0xFF


def test_profinet_rt_is_not_treated_as_dcp():
    frame = parse_frame(get_fixture("profinet_rt_non_dcp"))
    assert frame.kind == "profinet_other"
    assert frame.ethertype == 0x8892
    assert frame.frame_id == 0x8000
    assert frame.service_id is None


def test_non_profinet_ethertype():
    raw = bytes.fromhex("ffffffffffff0200000000110800") + b"\x45" + b"\x00" * 20
    frame = parse_frame(raw)
    assert frame.kind == "other"
    assert frame.ethertype == 0x0800


def test_vlan_response_decodes():
    raw = get_fixture("identify_response_named")
    vlan_raw = raw[:12] + b"\x81\x00\x00\x64" + raw[12:]
    frame = parse_frame(vlan_raw)
    assert frame.kind == "dcp"
    assert frame.vlan_id == 100
    identity = extract_device_identity(frame)
    assert identity is not None
    assert identity.name_of_station == "line-01.conveyor"


def test_get_response_blocks_use_block_info():
    frame = parse_frame(get_fixture("get_response_basic"))
    assert frame.kind == "dcp"
    assert frame.service_id == ServiceId.GET
    assert frame.service_type == ServiceType.RESPONSE_SUCCESS
    blocks = {(b.option, b.suboption): b for b in frame.blocks}
    ip_block = blocks[(1, 2)]
    assert ip_block.block_info == 0x0001
    assert len(ip_block.value) == 12
    name_block = blocks[(2, 2)]
    assert name_block.value == b"line-01.conveyor"
    id_block = blocks[(2, 3)]
    assert id_block.value == b"\x00\x2a\x01\x01"
    identity = extract_device_identity(frame)
    assert identity is not None
    assert identity.source == "get"
    assert identity.name_of_station == "line-01.conveyor"
    assert identity.ip_address == "192.0.2.11"
    assert identity.vendor_id == 0x002A


def test_identify_all_request_has_no_block_qualifier():
    raw = bytes.fromhex(
        "010ecf0000000800270faabb8892fefe05001234567800320004ffff0000"
    )
    frame = parse_frame(raw)
    assert frame.data_length == 4
    assert frame.warnings == []
    block = frame.blocks[0]
    assert (block.option, block.suboption) == (0xFF, 0xFF)
    assert block.block_length == 0
    assert block.block_info is None
    assert block.block_qualifier is None


def test_legacy_identify_all_with_block_qualifier_still_parses():
    # Tolerant parsing: older builds sent FF FF 00 02 00 00.
    raw = bytes.fromhex(
        "010ecf0000000800270faabb8892fefe05001234567800320006ffff00020000"
    )
    frame = parse_frame(raw)
    block = frame.blocks[0]
    assert block.block_length == 2
    assert block.block_qualifier == 0


def test_zero_padding_after_payload_is_not_a_warning():
    raw = bytes.fromhex(
        "010ecf0000000800270faabb8892fefe05001234567800320004ffff0000"
    ) + b"\x00" * 30
    frame = parse_frame(raw)
    assert not any("trailing" in warning for warning in frame.warnings)


def test_get_request_selectors_have_no_length_fields():
    raw = bytes.fromhex(
        "0200000000010200000000118892fefd0300aabbccdd00000006010202020203"
    )
    frame = parse_frame(raw)
    assert [(b.option, b.suboption) for b in frame.blocks] == [(1, 2), (2, 2), (2, 3)]
    assert all(b.block_length == 0 for b in frame.blocks)


def test_identify_name_filter_block_has_value_not_qualifier():
    raw = bytes.fromhex(
        "010ecf0000000800270faabb8892fefe05001234567800320014"
        "020200106c696e652d30312e636f6e7665796f72"
    )
    frame = parse_frame(raw)
    assert frame.warnings == []
    assert len(frame.blocks) == 1
    block = frame.blocks[0]
    assert (block.option, block.suboption) == (0x02, 0x02)
    assert block.block_length == 16
    assert block.block_qualifier is None
    assert block.value == b"line-01.conveyor"
    assert identify_filter_name(frame) == "line-01.conveyor"


def test_set_response_acknowledged_and_rejected():
    ack_payload = bytes.fromhex("0504000302020000")
    ack = _frame(
        src="02:00:00:00:00:11",
        dst="02:00:00:00:00:01",
        frame_id=FrameId.GET_SET,
        service_id=ServiceId.SET,
        service_type=ServiceType.RESPONSE_SUCCESS,
        xid=7,
        payload=ack_payload,
    )
    verdict, error, text = classify_set_response(parse_frame(ack))
    assert (verdict, error) == ("acknowledged", 0)
    assert "acknowledged" in text

    rejection = MockNetwork(default_mock_devices()[:1]).build_set_rejection(
        default_mock_devices()[0],
        parse_frame(
            bytes.fromhex(
                "0200000000110200000000018892fefd04001122334400000007020200000041"
            )
        ),
    )
    verdict, error, text = classify_set_response(parse_frame(rejection))
    assert verdict == "rejected"
    assert error == 0x05
    assert "not possible" in text.lower()

    unsupported = _frame(
        src="02:00:00:00:00:11",
        dst="02:00:00:00:00:01",
        frame_id=FrameId.GET_SET,
        service_id=ServiceId.SET,
        service_type=ServiceType.RESPONSE_NOT_SUPPORTED,
        xid=7,
        payload=b"",
    )
    verdict, error, _ = classify_set_response(parse_frame(unsupported))
    assert verdict == "service_not_supported"
    assert error is None


def test_nonzero_padding_warns():
    # One block 02/02: BlockInfo 0, value "A" (3 bytes total), then pad 0xff.
    payload = bytes.fromhex("02020003000041ff")
    raw = _frame(
        src="02:00:00:00:00:11",
        dst="02:00:00:00:00:01",
        frame_id=FrameId.IDENTIFY_RESPONSE,
        service_id=ServiceId.IDENTIFY,
        service_type=ServiceType.RESPONSE_SUCCESS,
        xid=1,
        payload=payload,
    )
    frame = parse_frame(raw)
    assert any("padding" in warning for warning in frame.warnings)


def test_random_bytes_never_raise():
    rng = random.Random(1234)
    for length in range(0, 128):
        for _ in range(3):
            raw = bytes(rng.randrange(256) for _ in range(length))
            frame = parse_frame(raw)
            assert frame.kind in ("dcp", "profinet_other", "other", "truncated")


def test_rsi_protocol_properties_and_cim_interface_are_named():
    """Hand-built blocks: 02/0a, 02/0b and 07/05 must decode by name.

    Layouts follow the Wireshark pn_dcp dissector (IEC 61158-6-10 section 4.3):
    02/0a and 02/0b carry a 16-bit capability bit field, 07/05 carries the
    CIM-VDI value VendorID(2) + DeviceID(2) + InstanceID(2).
    """
    payload = (
        b"\x02\x0a\x00\x04\x00\x00\x00\x1f"  # RSI properties, bits 0-4
        b"\x02\x0b\x00\x04\x00\x00\x00\x0f"  # Protocol properties, bits 0-3
        b"\x07\x05\x00\x08\x00\x00\x00\x2a\x12\x01\x00\x00"  # CIM interface
    )
    raw = _frame(
        src="02:00:00:00:00:11",
        dst="02:00:00:00:00:01",
        frame_id=FrameId.IDENTIFY_RESPONSE,
        service_id=ServiceId.IDENTIFY,
        service_type=ServiceType.RESPONSE_SUCCESS,
        xid=7,
        payload=payload,
    )
    frame = parse_frame(raw)
    assert frame.kind == "dcp"
    assert [(b.option, b.suboption) for b in frame.blocks] == [
        (0x02, 0x0A),
        (0x02, 0x0B),
        (0x07, 0x05),
    ]
    assert [b.suboption_name for b in frame.blocks] == [
        "RSI properties",
        "Protocol properties",
        "CIM interface",
    ]
    assert not any(b.unknown for b in frame.blocks)
    assert [b.value for b in frame.blocks] == [
        b"\x00\x1f",
        b"\x00\x0f",
        b"\x00\x2a\x12\x01\x00\x00",
    ]
    assert frame.warnings == []
