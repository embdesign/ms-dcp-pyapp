"""Functional test catalogue.

Pure data: the ID, title, category and description of every functional test the
runner can execute. Kept separate from :mod:`dcpstudio.testrunner.runner` so the
catalogue can be reviewed (and rendered by the GUI) without the engine.

Test IDs use a functional namespace (``env.*``, ``parser.*``, ``protocol.*``,
``validation.*``, ``write.*``) and are displayed verbatim in the GUI, the event
log and the HTML report. The runner derives its handler method from the ID:
``getattr(runner, f"_test_{test_id.replace('.', '_')}")``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class TestCase:
    test_id: str
    name: str
    category: str
    description: str
    live: bool
    default_enabled: bool = True
    implemented: bool = True


TEST_CASES: tuple[TestCase, ...] = (
    TestCase(
        "env.interface",
        "Selected interface sanity",
        "Environment",
        "Selected interface has a MAC, is not loopback-only, and has known link state.",
        live=True,
    ),
    TestCase(
        "env.readiness",
        "Capture readiness and privileges",
        "Environment",
        "Raw-capture privileges and Npcap/raw-socket availability.",
        live=True,
    ),
    TestCase(
        "env.capture",
        "Capture start",
        "Environment",
        "Start passive capture on the selected interface and verify it is running.",
        live=True,
    ),
    TestCase(
        "parser.fixture_decode",
        "Decode a known Identify response",
        "Offline parser",
        "Decode the synthetic named-device fixture and check required fields.",
        live=False,
    ),
    TestCase(
        "parser.malformed",
        "Defensive truncated/malformed parsing",
        "Offline parser",
        "Truncated and bad-length fixtures must never raise or over-read.",
        live=False,
    ),
    TestCase(
        "parser.pcap_roundtrip",
        "PCAP write/read roundtrip",
        "Offline parser",
        "Export a fixture to PCAP, re-import it, and compare bytes/timestamps.",
        live=False,
    ),
    TestCase(
        "parser.block_errors",
        "DCP block-error decoding",
        "Offline parser",
        "Decode every documented Control/Response block error 0x00–0x07.",
        live=False,
    ),
    TestCase(
        "protocol.transaction_matching",
        "Xid/target correlation with unrelated response",
        "Offline transactions",
        "A response with the wrong Xid must be logged as unrelated, not attributed.",
        live=False,
    ),
    TestCase(
        "protocol.get_offline",
        "Get request/response decode",
        "Offline parser",
        "Encode a multi-block Get request and decode the mock response.",
        live=False,
    ),
    TestCase(
        "protocol.identify_discovery",
        "Multicast Identify discovery",
        "Live DCP",
        "Send one standards-correct Identify-All request and collect responses.",
        live=True,
    ),
    TestCase(
        "protocol.get_live",
        "Live read-only Get",
        "Live DCP",
        "Read identity blocks from one discovered device with Get; no configuration.",
        live=True,
    ),
    TestCase(
        "protocol.unicast_identify",
        "Unicast Identify",
        "Live DCP",
        "Send Identify to one discovered device MAC; acceptance is device-dependent.",
        live=True,
    ),
    TestCase(
        "protocol.identity_before_after",
        "Before/after identity comparison",
        "Live DCP",
        "Two paced discoveries; compare name/IP/vendor/device identity. Read-only.",
        live=True,
    ),
    TestCase(
        "protocol.repeat_discovery",
        "Bounded repeated discovery",
        "Live DCP",
        "Three paced Identify requests; compare discovered device sets.",
        live=True,
    ),
    TestCase(
        "protocol.response_times",
        "Response-time measurement",
        "Live DCP",
        "Report min/max RTT from the latest discovery (measurement, not a pass/fail SLA).",
        live=True,
    ),
    TestCase(
        "validation.station_name",
        "PROFINET station-name validation",
        "Offline validation",
        "Check accepted/rejected names against PROFINET naming rules.",
        live=False,
    ),
    TestCase(
        "validation.ip_suite",
        "IPv4 suite validation",
        "Offline validation",
        "Check mask/gateway consistency and reserved-address rejection.",
        live=False,
    ),
    TestCase(
        "write.set_name",
        "Set NameOfStation (optional, guarded)",
        "State-changing (optional)",
        "Requires configuration mode, per-operation confirmation and a selected target. "
        "Sends one Set and one read-back Get; no retry.",
        live=True,
        default_enabled=False,
        implemented=True,
    ),
    TestCase(
        "write.set_ip",
        "Set IP parameters (optional, guarded)",
        "State-changing (optional)",
        "Requires configuration mode, per-operation confirmation and a selected target. "
        "Sends one Set and one read-back Get; no retry.",
        live=True,
        default_enabled=False,
        implemented=True,
    ),
    TestCase(
        "write.reset",
        "ResetToFactorySettings (optional, guarded)",
        "State-changing (optional)",
        "Requires configuration mode, per-operation confirmation and a selected target. "
        "Acknowledged resets are followed by one read-only post-check.",
        live=True,
        default_enabled=False,
        implemented=True,
    ),
)
