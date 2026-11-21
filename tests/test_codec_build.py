from __future__ import annotations

import struct

import pytest

from dcpstudio.codec import (
    DcpEncodingError,
    IdentifyFilter,
    build_get_request,
    build_identify_request,
    encode_block,
    identify_filter_name,
    pad_to_min_frame,
    parse_frame,
)


def test_identify_all_request_is_byte_exact():
    request = build_identify_request("08:00:27:0f:aa:bb", 0x12345678)
    assert request.hex() == (
        "010ecf000000"
        "0800270faabb"
        "8892"
        "fefe"
        "0500"
        "12345678"
        "0032"
        "0004"
        "ffff0000"
    )
    frame = parse_frame(request)
    assert frame.kind == "dcp"
    assert frame.service_id == 0x05
    assert frame.service_type == 0x00
    assert frame.xid == 0x12345678
    assert frame.response_delay_factor == 50
    assert frame.data_length == 4
    assert frame.warnings == []
    assert len(frame.blocks) == 1
    block = frame.blocks[0]
    assert (block.option, block.suboption) == (0xFF, 0xFF)
    assert block.block_length == 0
    assert block.block_info is None
    assert block.block_qualifier is None


def test_pad_to_min_frame_reaches_ethernet_minimum():
    request = build_identify_request("08:00:27:0f:aa:bb", 0x12345678)
    padded = pad_to_min_frame(request)
    assert len(padded) == 60
    assert padded[: len(request)] == request
    assert set(padded[len(request) :]) == {0}
    assert pad_to_min_frame(padded) == padded


def test_unicast_identify_uses_same_pdu_and_device_mac():
    request = build_identify_request(
        "08:00:27:0f:aa:bb", 0x01020304, dst_mac="02:00:00:00:00:11"
    )
    assert request[:6].hex() == "020000000011"
    frame = parse_frame(request)
    assert frame.frame_id == 0xFEFE
    assert frame.service_id == 0x05
    assert frame.blocks[0].block_length == 0
    assert frame.blocks[0].block_qualifier is None


def test_vlan_tag_inserted_and_parsed():
    request = build_identify_request(
        "08:00:27:0f:aa:bb", 0x12345678, vlan_id=100, vlan_priority=5
    )
    assert request[12:14] == b"\x81\x00"
    tci = struct.unpack_from("!H", request, 14)[0]
    assert (tci >> 13) == 5
    assert (tci & 0x0FFF) == 100
    frame = parse_frame(request)
    assert frame.vlan_id == 100
    assert frame.vlan_priority == 5
    assert frame.blocks[0].block_length == 0
    assert frame.blocks[0].block_qualifier is None


def test_get_request_is_only_option_suboption_pairs():
    request = build_get_request(
        "02:00:00:00:00:01",
        "02:00:00:00:00:11",
        0xAABBCCDD,
        [(1, 2), (2, 2), (2, 3)],
    )
    assert request.hex() == (
        "020000000011"  # destination: device MAC
        "020000000001"  # source: local interface MAC
        "8892"
        "fefd"
        "0300"
        "aabbccdd"
        "0000"
        "0006"
        "010202020203"
    )
    frame = parse_frame(request)
    assert frame.service_id == 0x03
    assert [(b.option, b.suboption) for b in frame.blocks] == [(1, 2), (2, 2), (2, 3)]


def test_xids_are_distinct():
    generated = {
        parse_frame(build_identify_request("02:00:00:00:00:01", n)).xid
        for n in range(1, 101)
    }
    assert len(generated) == 100


def test_invalid_response_delay_factor_rejected():
    with pytest.raises(DcpEncodingError):
        build_identify_request("02:00:00:00:00:01", 1, response_delay_factor=0)
    with pytest.raises(DcpEncodingError):
        build_identify_request("02:00:00:00:00:01", 1, response_delay_factor=6401)


def test_invalid_vlan_rejected():
    with pytest.raises(DcpEncodingError):
        build_identify_request("02:00:00:00:00:01", 1, vlan_id=0)
    with pytest.raises(DcpEncodingError):
        build_identify_request("02:00:00:00:00:01", 1, vlan_id=4095)


def test_block_length_excludes_padding():
    encoded = encode_block(0x02, 0x02, block_info=0, value=b"abc")
    assert len(encoded) % 2 == 0
    assert struct.unpack_from("!H", encoded, 2)[0] == 5  # info(2) + value(3)
    assert encoded[-1] == 0


def test_identify_name_filter_request_is_byte_exact():
    name = "line-01.conveyor"
    request = build_identify_request(
        "08:00:27:0f:aa:bb", 0x12345678, name_of_station=name
    )
    assert request.hex() == (
        "010ecf000000"
        "0800270faabb"
        "8892"
        "fefe"
        "0500"
        "12345678"
        "0032"
        "0014"
        "02020010"
        "6c696e652d30312e636f6e7665796f72"
    )
    frame = parse_frame(request)
    assert frame.frame_id == 0xFEFE
    assert frame.service_id == 0x05
    assert frame.service_type == 0x00
    assert frame.data_length == 20
    assert len(frame.blocks) == 1
    block = frame.blocks[0]
    assert (block.option, block.suboption) == (0x02, 0x02)
    assert block.block_length == len(name)
    assert block.block_info is None
    assert block.block_qualifier is None
    assert block.value == name.encode("ascii")
    assert identify_filter_name(frame) == name


def test_identify_name_filter_odd_length_is_padded_without_counting_it():
    request = build_identify_request(
        "08:00:27:0f:aa:bb", 1, name_of_station="abc"
    )
    frame = parse_frame(request)
    block = frame.blocks[0]
    assert block.block_length == 3
    assert block.value == b"abc"
    # BlockLength excludes padding (3), but DCPDataLength is the raw payload
    # length: 4-byte block header + 3 value bytes + 1 padding byte = 8.
    assert frame.data_length == 8
    assert len(request) % 2 == 0


def test_identify_name_filter_rejects_empty_and_invalid_names():
    with pytest.raises(DcpEncodingError):
        build_identify_request("02:00:00:00:00:01", 1, name_of_station="")
    with pytest.raises(DcpEncodingError):
        build_identify_request("02:00:00:00:00:01", 1, name_of_station="Bad.Name")


def test_multi_block_identify_filter_is_ordered_and_encoded():
    filters = IdentifyFilter(
        name_of_station="line-01.conveyor",
        alias="port-001.line-01.conveyor",
        vendor_name="Mock Automation",
        vendor_id=0x002A,
        device_id=0x0101,
        device_role=0x01,
        mac="02:00:00:00:00:11",
    )
    frame = parse_frame(
        build_identify_request("08:00:27:0f:aa:bb", 7, filters=filters)
    )
    assert [(b.option, b.suboption) for b in frame.blocks] == [
        (0x02, 0x02),
        (0x02, 0x06),
        (0x02, 0x01),
        (0x02, 0x03),
        (0x02, 0x04),
        (0x01, 0x01),
    ]
    assert frame.blocks[3].value == b"\x00\x2a\x01\x01"
    assert frame.blocks[4].value == b"\x01\x00"
    assert frame.blocks[5].value == bytes.fromhex("020000000011")
    assert frame.service_id == 0x05 and frame.service_type == 0x00
    assert filters.summary.startswith("name 'line-01.conveyor'")


def test_identify_filter_validation():
    with pytest.raises(DcpEncodingError):
        IdentifyFilter().encode()
    with pytest.raises(DcpEncodingError):
        IdentifyFilter(vendor_id=1).encode()
    with pytest.raises(DcpEncodingError):
        IdentifyFilter(device_role=256).encode()
    with pytest.raises(DcpEncodingError):
        build_identify_request(
            "02:00:00:00:00:01",
            1,
            name_of_station="a",
            filters=IdentifyFilter(name_of_station="b"),
        )


def test_identify_all_has_no_name_filter():
    frame = parse_frame(build_identify_request("02:00:00:00:00:01", 1))
    assert identify_filter_name(frame) is None


def test_identify_destination_must_be_dcp_multicast_or_a_device():
    for bad in ("ff:ff:ff:ff:ff:ff", "01:0e:cf:00:00:01", "01:00:5e:00:00:01"):
        with pytest.raises(DcpEncodingError):
            build_identify_request("08:00:27:0f:aa:bb", 1, dst_mac=bad)
    # The DCP multicast MAC and a unicast device MAC are both valid.
    build_identify_request("08:00:27:0f:aa:bb", 1)
    build_identify_request("08:00:27:0f:aa:bb", 1, dst_mac="02:00:00:00:00:11")


def test_get_request_must_target_one_unicast_device():
    for bad in ("01:0e:cf:00:00:00", "ff:ff:ff:ff:ff:ff"):
        with pytest.raises(DcpEncodingError):
            build_get_request("08:00:27:0f:aa:bb", bad, 1, [(1, 2)])
    frame = parse_frame(
        build_get_request("08:00:27:0f:aa:bb", "02:00:00:00:00:11", 1, [(1, 2)])
    )
    assert frame.service_id == 0x03
    assert frame.response_delay_factor == 0
