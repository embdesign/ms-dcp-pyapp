from __future__ import annotations

import struct
from datetime import UTC, datetime

import pytest

from dcpstudio.fixtures import get_fixture
from dcpstudio.model import CapturedFrame
from dcpstudio.pcap_io import PcapError, analyze_pcap, read_pcap, write_pcap


def test_pcap_roundtrip_preserves_bytes_and_timestamp(tmp_path):
    timestamp = datetime(2026, 11, 11, 12, 34, 56, 789123, tzinfo=UTC)
    frames = [
        CapturedFrame(timestamp, "test0", "rx", get_fixture("identify_response_named")),
        CapturedFrame(timestamp, "test0", "tx", get_fixture("profinet_rt_non_dcp")),
    ]
    path = tmp_path / "roundtrip.pcap"
    assert write_pcap(path, frames) == 2
    records = read_pcap(path)
    assert len(records) == 2
    assert records[0].raw == frames[0].raw
    assert records[1].raw == frames[1].raw
    assert records[0].timestamp == timestamp


def test_generated_session_pcap_is_readable():
    frames = analyze_pcap("tests/fixtures/session.pcap")
    assert len(frames) == 14
    kinds = [frame.parsed.kind for frame in frames if frame.parsed]
    assert kinds.count("dcp") == 14
    services = [frame.parsed.service_name for frame in frames if frame.parsed]
    assert services.count("Identify") == 4
    assert services.count("Get") == 2
    assert services.count("Set") == 8


def test_bad_magic_rejected(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"\x00" * 24)
    with pytest.raises(PcapError):
        read_pcap(path)


def test_non_ethernet_linktype_rejected(tmp_path):
    path = tmp_path / "raw.pcap"
    path.write_bytes(
        struct.pack("!IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    )
    with pytest.raises(PcapError):
        read_pcap(path)


def test_truncated_record_rejected(tmp_path):
    path = tmp_path / "truncated.pcap"
    header = struct.pack("!IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_header = struct.pack("!IIII", 1, 0, 100, 100)
    path.write_bytes(header + record_header + b"short")
    with pytest.raises(PcapError):
        read_pcap(path)
