"""Regenerate offline fixtures used by the tests.

Run from the repository root:

    uv run python tools/make_fixtures.py

The frames come from the mock responder, not from real hardware. The script
writes tests/fixtures/*.hex and tests/fixtures/session.pcap.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from dcpstudio.codec import (
    build_get_request,
    build_identify_request,
    build_reset_to_factory_request,
    build_set_ip_request,
    build_set_name_request,
)
from dcpstudio.fixtures import FIXTURES
from dcpstudio.mock import MockNetwork, default_mock_devices
from dcpstudio.model import CapturedFrame
from dcpstudio.pcap_io import write_pcap


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    fixtures_dir = root / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    for name, hex_value in FIXTURES.items():
        (fixtures_dir / f"{name}.hex").write_text(hex_value + "\n", encoding="ascii")

    network = MockNetwork(default_mock_devices())
    request = build_identify_request("02:00:00:00:00:01", 0x11223344)
    responses = network.handle_request(request)
    get_request = build_get_request(
        "02:00:00:00:00:01",
        "02:00:00:00:00:11",
        0xAABBCCDD,
        [(1, 2), (2, 2), (2, 3)],
    )
    get_response = network.handle_request(get_request)[0]

    set_name_request = build_set_name_request(
        "02:00:00:00:00:01",
        "02:00:00:00:00:11",
        0x11223344,
        "line-01.conveyor",
        permanent=True,
    )
    set_name_response = network.handle_request(set_name_request)[0]
    set_ip_request = build_set_ip_request(
        "02:00:00:00:00:01",
        "02:00:00:00:00:11",
        0x11223344,
        "192.0.2.11",
        "255.255.255.0",
        "192.0.2.1",
        permanent=False,
    )
    set_ip_response = network.handle_request(set_ip_request)[0]
    reset_request = build_reset_to_factory_request(
        "02:00:00:00:00:01", "02:00:00:00:00:11", 0x11223344, 8
    )
    reset_response = network.handle_request(reset_request)[0]

    reject_network = MockNetwork([default_mock_devices()[0]], apply_set=False)
    rejected_request = build_set_name_request(
        "02:00:00:00:00:01",
        "02:00:00:00:00:11",
        0x11223344,
        "line-01.conveyor",
        permanent=True,
    )
    rejected_response = reject_network.handle_request(rejected_request)[0]

    base = datetime(2026, 11, 11, 12, 0, 0, tzinfo=UTC)
    frames = [
        CapturedFrame(base, "fixture", "tx", request),
        *[
            CapturedFrame(base, "fixture", "rx", response)
            for response in responses
        ],
        CapturedFrame(base, "fixture", "tx", get_request),
        CapturedFrame(base, "fixture", "rx", get_response),
        CapturedFrame(base, "fixture", "tx", set_name_request),
        CapturedFrame(base, "fixture", "rx", set_name_response),
        CapturedFrame(base, "fixture", "tx", set_ip_request),
        CapturedFrame(base, "fixture", "rx", set_ip_response),
        CapturedFrame(base, "fixture", "tx", reset_request),
        CapturedFrame(base, "fixture", "rx", reset_response),
        CapturedFrame(base, "fixture", "tx", rejected_request),
        CapturedFrame(base, "fixture", "rx", rejected_response),
    ]
    pcap_path = fixtures_dir / "session.pcap"
    write_pcap(pcap_path, frames)

    print(f"Wrote {len(FIXTURES)} hex fixtures and {pcap_path.name} ({len(frames)} frames)")
    for name in FIXTURES:
        print(f"  {name}.hex")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
