from __future__ import annotations

from dcpstudio.codec import (
    build_get_request,
    build_identify_request,
    build_reset_to_factory_request,
    build_set_ip_request,
    build_set_name_request,
)
from dcpstudio.fixtures import FIXTURES, get_fixture
from dcpstudio.mock import MockNetwork, default_mock_devices


def test_named_fixture_matches_mock_responder():
    network = MockNetwork(default_mock_devices())
    responses = network.handle_request(build_identify_request("02:00:00:00:00:01", 0x11223344))
    assert responses[0].hex() == FIXTURES["identify_response_named"]
    assert responses[2].hex() == FIXTURES["identify_response_unnamed"]


def test_get_fixture_matches_mock_responder():
    network = MockNetwork(default_mock_devices())
    request = build_get_request(
        "02:00:00:00:00:01", "02:00:00:00:00:11", 0xAABBCCDD, [(1, 2), (2, 2), (2, 3)]
    )
    assert network.handle_request(request)[0].hex() == FIXTURES["get_response_basic"]
    assert get_fixture("identify_response_named") == bytes.fromhex(
        FIXTURES["identify_response_named"]
    )


def test_set_and_reset_fixtures_match_mock_responder():
    network = MockNetwork(default_mock_devices())
    name_request = build_set_name_request(
        "02:00:00:00:00:01",
        "02:00:00:00:00:11",
        0x11223344,
        "line-01.conveyor",
        permanent=True,
    )
    assert name_request.hex() == FIXTURES["set_name_request"]
    assert (
        network.handle_request(name_request)[0].hex()
        == FIXTURES["set_name_response_ack"]
    )

    ip_request = build_set_ip_request(
        "02:00:00:00:00:01",
        "02:00:00:00:00:11",
        0x11223344,
        "192.0.2.11",
        "255.255.255.0",
        "192.0.2.1",
        permanent=False,
    )
    assert ip_request.hex() == FIXTURES["set_ip_request"]
    assert network.handle_request(ip_request)[0].hex() == FIXTURES["set_ip_response_ack"]

    reset_request = build_reset_to_factory_request(
        "02:00:00:00:00:01", "02:00:00:00:00:11", 0x11223344, 8
    )
    assert reset_request.hex() == FIXTURES["reset_request_mode8"]
    assert (
        network.handle_request(reset_request)[0].hex()
        == FIXTURES["reset_response_ack"]
    )

    reject_network = MockNetwork([default_mock_devices()[0]], apply_set=False)
    assert (
        reject_network.handle_request(name_request)[0].hex()
        == FIXTURES["set_name_response_rejected"]
    )
