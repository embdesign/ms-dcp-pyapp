from __future__ import annotations

import pytest

from dcpstudio.codec import (
    DcpEncodingError,
    build_factory_reset_legacy_request,
    build_reset_to_factory_request,
    build_set_ip_request,
    build_set_name_request,
    build_signal_request,
    parse_frame,
    request_qualifier,
)
from dcpstudio.constants import FrameId, ServiceId, ServiceType

SRC = "02:00:00:00:00:01"
DST = "02:00:00:00:00:11"
XID = 0x11223344


def test_set_name_request_golden_vector_permanent():
    raw = build_set_name_request(
        SRC, DST, XID, "line-01.conveyor", permanent=True
    )
    assert raw.hex() == (
        "0200000000110200000000018892fefd04001122334400000016"
        "0202001200016c696e652d30312e636f6e7665796f72"
    )
    frame = parse_frame(raw)
    assert frame.frame_id == FrameId.GET_SET
    assert frame.service_id == ServiceId.SET
    assert frame.service_type == ServiceType.REQUEST
    assert frame.blocks[0].block_qualifier == 0x0001
    assert frame.blocks[0].value == b"line-01.conveyor"


def test_set_name_request_temporary_and_empty_name():
    raw = build_set_name_request(SRC, DST, XID, "", permanent=False)
    assert raw.hex() == (
        "0200000000110200000000018892fefd04001122334400000006"
        "020200020000"
    )
    block = parse_frame(raw).blocks[0]
    assert block.block_qualifier == 0x0000
    assert block.value == b""


def test_set_ip_request_golden_vector():
    raw = build_set_ip_request(
        SRC,
        DST,
        XID,
        "192.0.2.11",
        "255.255.255.0",
        "192.0.2.1",
        permanent=False,
    )
    assert raw.hex() == (
        "0200000000110200000000018892fefd04001122334400000012"
        "0102000e0000c000020bffffff00c0000201"
    )
    block = parse_frame(raw).blocks[0]
    assert block.block_qualifier == 0x0000
    assert block.value == bytes.fromhex("c000020bffffff00c0000201")


def test_set_ip_request_empty_gateway_is_zero():
    raw = build_set_ip_request(
        SRC, DST, XID, "10.0.0.2", "255.0.0.0", "", permanent=True
    )
    block = parse_frame(raw).blocks[0]
    assert block.value == bytes.fromhex("0a000002ff00000000000000")


def test_reset_request_golden_vector_mode_8():
    raw = build_reset_to_factory_request(SRC, DST, XID, 8)
    assert raw.hex() == (
        "0200000000110200000000018892fefd04001122334400000006"
        "050600020010"
    )
    block = parse_frame(raw).blocks[0]
    assert (block.option, block.suboption) == (0x05, 0x06)
    assert block.block_qualifier == 0x0010
    assert block.value == b""


def test_reset_request_refuses_unverified_modes():
    for mode in (0, 3, 5, 7, 9, 99):
        with pytest.raises(DcpEncodingError):
            build_reset_to_factory_request(SRC, DST, XID, mode)


def test_legacy_factory_reset_request_golden_vector():
    raw = build_factory_reset_legacy_request(SRC, DST, XID)
    assert raw.hex() == (
        "0200000000110200000000018892fefd04001122334400000006"
        "050500020000"
    )
    block = parse_frame(raw).blocks[0]
    assert (block.option, block.suboption) == (0x05, 0x05)
    assert block.block_qualifier == 0x0000
    assert block.value == b""


def test_state_changing_builders_refuse_multicast_or_broadcast():
    for target in ("01:0e:cf:00:00:00", "ff:ff:ff:ff:ff:ff"):
        with pytest.raises(DcpEncodingError):
            build_set_name_request(SRC, target, XID, "line-01", permanent=True)
        with pytest.raises(DcpEncodingError):
            build_reset_to_factory_request(SRC, target, XID, 8)
        with pytest.raises(DcpEncodingError):
            build_factory_reset_legacy_request(SRC, target, XID)


def test_builders_validate_parameters():
    with pytest.raises(DcpEncodingError):
        build_set_name_request(SRC, DST, XID, "UPPERCASE", permanent=True)
    with pytest.raises(DcpEncodingError):
        build_set_ip_request(
            SRC, DST, XID, "192.168.1.10", "255.0.255.0", "192.168.1.1", permanent=True
        )


def test_request_qualifier_matches_the_encoders():
    """The display helper and the encoders must never disagree."""
    assert request_qualifier("set_name", permanent=True) == 0x0001
    assert request_qualifier("set_name", permanent=False) == 0x0000
    assert request_qualifier("set_ip", permanent=True) == 0x0001
    assert request_qualifier("reset", reset_mode=8) == 0x0010
    assert request_qualifier("reset_legacy") == 0x0000

    encoded = {
        ("set_name", True): build_set_name_request(SRC, DST, XID, "line-01", permanent=True),
        ("set_name", False): build_set_name_request(SRC, DST, XID, "line-01", permanent=False),
        ("reset", 8): build_reset_to_factory_request(SRC, DST, XID, 8),
        ("reset_legacy", None): build_factory_reset_legacy_request(SRC, DST, XID),
    }
    for key, raw in encoded.items():
        block = parse_frame(raw).blocks[0]
        if key[0] == "reset":
            value = request_qualifier("reset", reset_mode=key[1])
        elif key[0] == "reset_legacy":
            value = request_qualifier("reset_legacy")
        else:
            value = request_qualifier(key[0], permanent=key[1])
        assert block.block_qualifier == value, key

    with pytest.raises(DcpEncodingError):
        request_qualifier("delete_everything")


def test_signal_request_golden_vector():
    """05/03 carries BlockQualifier + SignalValue 0x0100 (Wireshark layout)."""
    raw = build_signal_request(SRC, DST, XID)
    assert raw.hex() == (
        "0200000000110200000000018892fefd04001122334400000008"
        "0503000400000100"
    )
    block = parse_frame(raw).blocks[0]
    assert (block.option, block.suboption) == (0x05, 0x03)
    assert block.block_length == 4
    assert block.block_qualifier == 0x0000
    assert block.value == b"\x01\x00"


def test_signal_request_refuses_unverified_signal_values():
    for value in (0x0000, 0x0001, 0x0101, 0x0200, 0xFFFF):
        with pytest.raises(DcpEncodingError):
            build_signal_request(SRC, DST, XID, signal_value=value)


def test_signal_request_refuses_multicast_or_broadcast():
    for target in ("01:0e:cf:00:00:00", "ff:ff:ff:ff:ff:ff"):
        with pytest.raises(DcpEncodingError):
            build_signal_request(SRC, target, XID)
