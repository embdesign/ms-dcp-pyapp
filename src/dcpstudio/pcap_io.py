"""Minimal, defensive PCAP (classic libpcap, Ethernet) reader/writer.

A small in-project implementation is used instead of relying on linker/runtime
pcap behaviour during export. It preserves capture timestamps and is fully
unit-testable. Live capture still uses Scapy/Npcap.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .codec import parse_frame
from .model import CapturedFrame

PCAP_MAGIC_USEC_BE = 0xA1B2C3D4
PCAP_MAGIC_USEC_LE = 0xD4C3B2A1
PCAP_MAGIC_NSEC_BE = 0xA1B23C4D
PCAP_MAGIC_NSEC_LE = 0x4D3CB2A1
LINKTYPE_ETHERNET = 1
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_FRAMES = 250_000


class PcapError(ValueError):
    pass


@dataclass(slots=True)
class PcapRecord:
    timestamp: datetime
    raw: bytes
    original_length: int


def write_pcap(path: str | Path, frames: Iterable[CapturedFrame]) -> int:
    """Write classic pcap (big-endian, microsecond resolution, Ethernet)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("wb") as handle:
        handle.write(
            struct.pack(
                "!IHHIIII",
                PCAP_MAGIC_USEC_BE,
                2,
                4,
                0,
                0,
                65535,
                LINKTYPE_ETHERNET,
            )
        )
        for frame in frames:
            ts = frame.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            ts = ts.astimezone(UTC)
            seconds = int(ts.timestamp())
            micros = ts.microsecond
            raw = bytes(frame.raw)
            if len(raw) > MAX_RECORD_BYTES:
                raise PcapError(f"Frame of {len(raw)} bytes exceeds the PCAP safety limit")
            handle.write(struct.pack("!IIII", seconds, micros, len(raw), len(raw)))
            handle.write(raw)
            count += 1
    return count


def read_pcap(path: str | Path, *, max_frames: int = MAX_FRAMES) -> list[PcapRecord]:
    path = Path(path)
    data = path.read_bytes()
    if len(data) < 24:
        raise PcapError("File is shorter than a pcap global header")
    magic = struct.unpack_from("!I", data, 0)[0]
    if magic == PCAP_MAGIC_USEC_BE:
        endian = ">"
        nanos = False
    elif magic == PCAP_MAGIC_NSEC_BE:
        endian = ">"
        nanos = True
    elif magic == PCAP_MAGIC_USEC_LE:
        endian = "<"
        nanos = False
    elif magic == PCAP_MAGIC_NSEC_LE:
        endian = "<"
        nanos = True
    else:
        raise PcapError(f"Unsupported pcap magic 0x{magic:08x}")

    version_major, version_minor, _zone, _sigfigs, _snaplen, network = struct.unpack_from(
        f"{endian}HHIIII", data, 4
    )
    if (version_major, version_minor) != (2, 4):
        raise PcapError(f"Unsupported pcap version {version_major}.{version_minor}")
    if network != LINKTYPE_ETHERNET:
        raise PcapError(f"Only Ethernet (DLT 1) pcap files are supported, got DLT {network}")

    records: list[PcapRecord] = []
    offset = 24
    while offset + 16 <= len(data):
        if len(records) >= max_frames:
            raise PcapError(f"pcap contains more than the {max_frames}-frame safety limit")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        if incl_len > MAX_RECORD_BYTES:
            raise PcapError(f"pcap record length {incl_len} exceeds the safety limit")
        if offset + incl_len > len(data):
            raise PcapError("Truncated pcap record at end of file")
        raw = data[offset : offset + incl_len]
        offset += incl_len
        try:
            if nanos:
                timestamp = datetime.fromtimestamp(
                    ts_sec + ts_frac / 1_000_000_000, tz=UTC
                )
            else:
                timestamp = datetime.fromtimestamp(ts_sec + ts_frac / 1_000_000, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise PcapError(f"Invalid pcap timestamp: {exc}") from exc
        records.append(PcapRecord(timestamp=timestamp, raw=raw, original_length=orig_len))
    if offset != len(data):
        raise PcapError(f"{len(data) - offset} trailing byte(s) after the last pcap record")
    return records


def analyze_pcap(path: str | Path, *, interface_id: str = "pcap") -> list[CapturedFrame]:
    records = read_pcap(path)
    return [
        CapturedFrame(
            timestamp=record.timestamp,
            interface_id=interface_id,
            direction="rx",
            raw=record.raw,
            parsed=parse_frame(
                record.raw,
                captured_at=record.timestamp,
                interface_id=interface_id,
                direction="rx",
            ),
        )
        for record in records
    ]
