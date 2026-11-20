"""Functional test catalogue, its categories and the selectable suites.

Pure data: the ID, title, category, mode and description of every functional
test the runner can execute, plus the ordered category list and the named
suites an operator can select in one action. Kept separate from
:mod:`dcpstudio.testrunner.runner` so the catalogue can be reviewed (and
rendered by the GUI) without the engine.

Test IDs use a functional namespace (``env.*``, ``parser.*``, ``protocol.*``,
``validation.*``, ``write.*``) and are displayed verbatim in the GUI, the event
log and the HTML report. The runner derives its handler method from the ID:
``getattr(runner, f"_test_{test_id.replace('.', '_')}")``.

Grouping rules:

* ``category`` is the operator-facing group, shown once above its tests in the
  GUI and kept in the result/report vocabulary. ``TEST_GROUPS`` fixes the
  display order and the one-line explanation of each group.
* A **suite** is a named subset of test IDs. The device validation suites
  include the state-changing ``write.*`` tests, because a device is not
  validated until Set Name, Set IP and Reset have been attempted against it.
  ``TestSuite.sends_writes`` tells the caller that a suite needs a declared
  device under test and write authorization. ``DEVICE_READ_ONLY_SUITE`` and
  ``TOOL_SELF_TEST_SUITE`` never transmit a state-changing frame.
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

    @property
    def mode_text(self) -> str:
        """Short operator-facing mode label used by the test table."""
        base = "live" if self.live else "offline"
        return f"{base} · guarded" if not self.default_enabled else base


@dataclass(frozen=True, slots=True)
class TestSuite:
    """A named subset of test IDs that can be selected in one action."""

    key: str
    title: str
    description: str
    test_ids: tuple[str, ...]

    @property
    def sends_writes(self) -> bool:
        """True when the suite contains a state-changing ``write.*`` test."""
        return any(test_id.startswith("write.") for test_id in self.test_ids)

    @property
    def write_test_ids(self) -> tuple[str, ...]:
        return tuple(
            test_id for test_id in self.test_ids if test_id.startswith("write.")
        )


# Display order of the categories and the note shown above each group in the
# GUI. Every ``TestCase.category`` must be one of these keys; the tests enforce
# that no category is unreachable or omitted.
TEST_GROUPS: tuple[tuple[str, str], ...] = (
    (
        "Environment",
        "Local interface, capture privileges and capture start. A failure here makes "
        "the live results below meaningless.",
    ),
    (
        "Offline parser",
        "Decodes the synthetic fixtures that ship with the application. Transmits "
        "nothing and needs no privileges.",
    ),
    (
        "Offline transactions",
        "Correlation of responses to requests in the offline mock network.",
    ),
    (
        "Offline validation",
        "Station-name and IPv4 parameter rules used before any guarded write.",
    ),
    (
        "Live DCP",
        "Read-only Identify and Get traffic on the selected interface. Never "
        "configures a device.",
    ),
    (
        "State-changing (optional)",
        "Set/Reset operations sent once to the declared device under test; at most "
        "one per test run.",
    ),
)


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
        "protocol.identity_completeness",
        "Identity blocks complete",
        "Live DCP",
        "Check that each responder advertises DeviceProperties (vendor/device ID) and "
        "its supported options; a missing name or IP is reported as a warning, not a "
        "failure.",
        live=True,
    ),
    TestCase(
        "protocol.address_conflicts",
        "Duplicate NameOfStation/IP detection",
        "Live DCP",
        "Compare the discovered devices for a NameOfStation or IPv4 parameter that is "
        "advertised by more than one MAC. Read-only; transmits one ordinary Identify.",
        live=True,
    ),
    TestCase(
        "protocol.get_live",
        "Live read-only Get",
        "Live DCP",
        "Read identity blocks from one device with Get; no configuration.",
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
        "Set NameOfStation (optional)",
        "State-changing (optional)",
        "Requires a declared device under test and per-operation authorization. "
        "Sends one Set and one read-back Get; no retry.",
        live=True,
        default_enabled=False,
        implemented=True,
    ),
    TestCase(
        "write.set_ip",
        "Set IP parameters (optional)",
        "State-changing (optional)",
        "Requires a declared device under test and per-operation authorization. "
        "Sends one Set and one read-back Get; no retry.",
        live=True,
        default_enabled=False,
        implemented=True,
    ),
    TestCase(
        "write.reset",
        "ResetToFactorySettings (optional)",
        "State-changing (optional)",
        "Requires a declared device under test and per-operation authorization. "
        "Acknowledged resets are followed by one read-only post-check.",
        live=True,
        default_enabled=False,
        implemented=True,
    ),
)


def cases_by_id() -> dict[str, TestCase]:
    """Catalogue indexed by test ID (the ID is the stable contract)."""
    return {case.test_id: case for case in TEST_CASES}


def grouped_cases() -> tuple[tuple[str, str, tuple[TestCase, ...]], ...]:
    """Catalogue grouped as ``(category, note, cases)`` in ``TEST_GROUPS`` order.

    Empty groups are omitted, so a build that disables a whole category does not
    leave an empty heading behind.
    """
    buckets: dict[str, list[TestCase]] = {name: [] for name, _ in TEST_GROUPS}
    for case in TEST_CASES:
        buckets[case.category].append(case)
    return tuple(
        (name, note, tuple(buckets[name])) for name, note in TEST_GROUPS if buckets[name]
    )


def default_test_ids() -> tuple[str, ...]:
    """Every implemented test that runs without a per-operation confirmation."""
    return tuple(
        case.test_id for case in TEST_CASES if case.implemented and case.default_enabled
    )


def suite_test_ids(suite: TestSuite) -> tuple[str, ...]:
    """The suite's IDs restricted to the tests this build implements."""
    implemented = {case.test_id for case in TEST_CASES if case.implemented}
    return tuple(test_id for test_id in suite.test_ids if test_id in implemented)


def suite_by_key(key: str) -> TestSuite | None:
    for suite in TEST_SUITES:
        if suite.key == key:
            return suite
    return None


# The offline half of the full suite: proves the tool itself before it is
# trusted to judge a device capture.
TOOL_SELF_TEST_SUITE = TestSuite(
    key="tool-self-test",
    title="Tool self-test (offline)",
    description=(
        "Decoder, PCAP, block-error, correlation and validation checks against the "
        "synthetic fixtures. Transmits nothing and needs no privileges."
    ),
    test_ids=(
        "parser.fixture_decode",
        "parser.malformed",
        "parser.pcap_roundtrip",
        "parser.block_errors",
        "protocol.get_offline",
        "protocol.transaction_matching",
        "validation.station_name",
        "validation.ip_suite",
    ),
)

# The read-only half: establishes whether a DCP-capable device answers Identify
# and Get and reports a complete identity. It contains no Set or Reset, so it is
# safe on any device that is not being commissioned.
_DEVICE_READ_ONLY_IDS: tuple[str, ...] = (
    "env.interface",
    "env.readiness",
    "env.capture",
    "protocol.identify_discovery",
    "protocol.identity_completeness",
    "protocol.address_conflicts",
    "protocol.get_live",
    "protocol.unicast_identify",
    "protocol.identity_before_after",
    "protocol.repeat_discovery",
    "protocol.response_times",
)

DEVICE_READ_ONLY_SUITE = TestSuite(
    key="device-read-only",
    title="Device read-only checks",
    description=(
        "Environment and capture prerequisites plus every read-only Identify/Get "
        "check, in the order that makes the later results meaningful. Never "
        "transmits a Set or a Reset."
    ),
    test_ids=_DEVICE_READ_ONLY_IDS,
)

# The complete validation: read checks first, then exactly one Set NameOfStation,
# one Set IP and one ResetToFactorySettings against the declared device under
# test. Each state-changing frame is single-shot, freshly revalidated and read
# back; there is no retry and no rollback. The device is not validated until
# these have been attempted, so they are part of the suite rather than an extra.
DEVICE_VALIDATION_SUITE = TestSuite(
    key="device-validation",
    title="Device validation suite",
    description=(
        "Complete validation of one DCP-capable device: the read-only Identify/Get "
        "checks followed by one Set NameOfStation, one Set IP and one "
        "ResetToFactorySettings. Needs a declared device under test; the name/IP "
        "values come from the Configuration tab and the "
        "reset mode from the Reset tab. Each state-changing frame is sent once, "
        "revalidated and read back; no retry, no rollback."
    ),
    test_ids=_DEVICE_READ_ONLY_IDS
    + ("write.set_name", "write.set_ip", "write.reset"),
)

FULL_VALIDATION_SUITE = TestSuite(
    key="full-validation",
    title="Full validation suite",
    description=(
        "The tool self-test followed by the device validation suite (read-only "
        "checks plus the three state-changing tests). Needs a declared device under "
        "test."
    ),
    test_ids=TOOL_SELF_TEST_SUITE.test_ids + DEVICE_VALIDATION_SUITE.test_ids,
)

# Selection order in the GUI preset control. The two validation suites contain
# the ``write.*`` tests; the read-only and offline suites never do.
TEST_SUITES: tuple[TestSuite, ...] = (
    FULL_VALIDATION_SUITE,
    DEVICE_VALIDATION_SUITE,
    DEVICE_READ_ONLY_SUITE,
    TOOL_SELF_TEST_SUITE,
)
