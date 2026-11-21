Act as a senior Python developer and industrial Ethernet / PROFINET engineer. Create a maintainable desktop application for PROFINET DCP device discovery, configuration, and functional testing.

Use Python, PySide6 for the GUI, and an appropriate Ethernet packet library such as Scapy. Manage the project with uv and pyproject.toml. Support native Windows and Linux installations without Docker.

Before coding:
- Verify the actual APIs of the chosen packet library and version.
- Verify DCP packet layouts and supported operations against authoritative PROFINET documentation and reliable implementations.
- Do not invent protocol constants, reset qualifiers, or library methods.
- Clearly identify features that cannot be implemented or verified with the available references.

1. Scope and transport

PROFINET DCP uses Layer 2 Ethernet communication, not a TCP connection.

The application must:
- Enumerate local network interfaces.
- Display interface name, MAC address, link status, and IP addresses where available.
- Require explicit selection of one interface.
- Explain that discovery normally operates within the same Layer 2 network and does not traverse IP routers.
- Support Ethernet EtherType 0x8892 while distinguishing DCP frames from other PROFINET traffic.
- Document raw-packet privileges on Linux and the required packet-capture driver, such as Npcap, on Windows.
- Report missing permissions and drivers clearly.

Do not implement unrelated PROFINET cyclic IO, controller commissioning, or firmware flashing.

2. Device discovery

Implement DCP Identify discovery using standards-correct requests and responses.

Show discovered devices in a table with available information:
- MAC address.
- NameOfStation.
- IP address, subnet mask, and gateway.
- Vendor ID and Device ID.
- Device role and advertised DCP options, when supplied.
- Interface on which the response was received.
- Last-seen timestamp.

Support:
- Configurable discovery timeout.
- Repeated manual discovery.
- Deduplication by interface and MAC address.
- Partial responses and unknown blocks.
- Selection of exactly one target device.

Do not infer device capabilities solely from its manufacturer name.

3. DCP operations

Implement verified, supported operations:
- Identify.
- Get for supported blocks.
- Set NameOfStation.
- Set IP parameters.
- Device signaling / identification indication where supported.
- Reset operations, including factory reset where supported.

For configuration:
- Validate station names using PROFINET naming rules.
- Validate IPv4 addresses, subnet masks, and gateway consistency.
- Clearly distinguish temporary and persistent settings where the protocol supports this.
- Explain possible communication loss and naming/IP conflicts.
- Do not claim that DCP discovery proves an IP address is unused.

For reset:
- Distinguish reset variants and their documented scope.
- Do not assume that every device supports every reset mode.
- Do not assume that a DCP factory reset erases all application data, firmware, or vendor-specific configuration.
- Show the exact documented reset operation and qualifier.
- If support or semantics are unknown, explain the uncertainty and do not send a guessed command.

Where an operation requires a multi-block transaction or control sequence, implement the verified sequence rather than treating each block as an independent command.

4. Mandatory safety controls

Default to passive capture and user-triggered discovery/read operations.

Require one explicit confirmation before any state-changing operation.

Before setting parameters or resetting a device:
- Show the selected interface and target MAC address.
- Show the currently discovered device identity.
- Show the exact operation and proposed parameters.
- Explain that the action may interrupt machine communication or affect physical equipment.
- Require the user to confirm authorization and that the equipment is in a safe maintenance state.

For factory reset:
- Do not require typing the target MAC address or a confirmation phrase. The two mandatory checks (authorization and safe maintenance state) are sufficient for factory reset.
- Show the target MAC address prominently in the confirmation dialog so the operator can verify it visually.
- Revalidate target identity immediately before transmission.
- Send only to the explicitly selected target.
- Never provide batch reset or broadcast reset functionality.

Additional safeguards:
- No automatic changes during discovery.
- No automatic retries for state-changing commands.
- No automatic rollback after a timeout.
- No continuous scanning by default.
- Use conservative request-rate limits.
- Never interpret a missing response as proof that an operation failed.
- Recommend an isolated test network for development and validation.

5. Protocol implementation and diagnostics

Separate packet construction, parsing, transport, and transaction tracking.

Implement:
- Standards-correct frame IDs, service IDs, service types, and transaction identifiers.
- Correct option/suboption encoding.
- Correct lengths, byte order, alignment, and padding.
- Response correlation using transaction ID, service, and target identity.
- Explicit handling of DCP block errors.
- Timeouts and late, duplicate, or unrelated responses.
- Defensive parsing of truncated, malformed, and unknown blocks.

Display outcomes distinctly:
- Request transmitted.
- Matching response received.
- Operation acknowledged or rejected.
- Result independently verified through a subsequent discovery/read.
- Outcome unknown.

An acknowledgement must not automatically be reported as proof that a reset completed successfully.

For reset verification, consider that a device may reboot or stop responding temporarily. Do not resend the reset automatically.

6. General DCP functional testing

Provide a test runner for:
- Interface and capture readiness.
- Identify discovery.
- Unicast Identify where supported.
- Get requests for supported blocks.
- Response decoding and transaction matching.
- DCP error reporting.
- Repeated discovery with bounded request rates.
- Response-time measurements.
- Before/after comparison of device identity and network parameters.

Make configuration and reset tests optional, explicitly enabled, and protected by the same confirmation controls.

Use mocked transport or offline packet fixtures for malformed-packet and parser robustness tests. Do not send fuzzing traffic to live equipment.

Label results as functional/interoperability tests, not official PROFINET conformance certification.

7. Capture, logs, and reporting

Provide:
- A structured transaction log.
- Decoded request/response details.
- Hexadecimal packet inspection.
- Optional PCAP export and offline PCAP analysis.
- Capture filters focused on DCP traffic on the selected interface.

Export JSON and HTML reports containing:
- Test configuration and selected interface.
- Target identity.
- UTC timestamps.
- Operations, parameters, and transaction identifiers.
- Response codes and timing.
- Passed, failed, skipped, and inconclusive results.
- Before/after observations.
- Known limitations.

Warn that captures and reports can contain sensitive device identifiers and network configuration.

8. GUI and architecture

Provide tabs for:
- Interfaces and discovery.
- Device details.
- Configuration.
- Reset.
- Test runner.
- Packet capture.
- Logs and reports.

Keep the GUI responsive during packet capture and waiting for responses. Support cancellation and clean shutdown of capture handles and worker tasks.

Separate modules for:
- GUI.
- Platform-specific Ethernet transport.
- DCP encoder and decoder.
- Discovery and transaction services.
- Safety/confirmation workflow.
- Test runner.
- PCAP handling.
- Reporting and configuration.

9. Deliverables and implementation phases

Deliver:
- Complete runnable source code, not pseudocode.
- pyproject.toml and uv installation/run commands.
- Windows and Linux setup documentation.
- Unit tests for encoding and parsing.
- Offline packet fixtures with documented provenance.
- A mock DCP responder for automated tests.
- Integration-test instructions for an isolated lab.
- A protocol-support matrix identifying verified and unsupported operations.
- Troubleshooting for permissions, Npcap, interface selection, VLAN boundaries, and timeouts.

Implement in phases:
1. Interface selection, passive decoding, Identify discovery, and reporting.
2. Get operations and read-only functional tests.
3. Confirmation-protected station-name and IP configuration.
4. Verified reset variants with mandatory confirmation and post-action checks.

First present the architecture, dependencies, protocol references, and support matrix. Then implement phase 1 completely.

Do not implement a destructive operation until its wire encoding and semantics are verified. Clearly state limitations instead of presenting speculative functionality as working.

10. Implemented in the delivered build (beyond this brief)

The delivered `dcpstudio` 0.1.2 build also includes the following capabilities.
They are verified against the references in `docs/references.md`, recorded in
`docs/protocol-support-matrix.md`, and none of them weakens the safety model
above.

Operator surfaces:
- Headless CLI `dcp-cli` (also `python -m dcpstudio COMMAND`) over the same
  services, codec, operations catalogue and safety gate as the GUI:
  `interfaces`, `discover`, `monitor`, `get`, `signal`, `set-name`, `set-ip`,
  `reset`, `tests`, `pcap`. State-changing commands require `--confirm` and
  `tests --include-writes --confirm --mac` runs the write cases; `--json` keeps stdout
  machine-readable; `--report PATH` writes JSON or HTML; exit codes are 0 for
  success, 1 for error/refusal, and 2 for inconclusive/outcome unknown.
- Eight-tab desktop GUI: Interfaces & Discovery, Monitor, Device Details,
  Configuration, Reset, Test Runner, Packet Capture, and Logs & Reports.
- A `demo0` mock interface with three simulated devices, usable without
  hardware or raw-packet privileges; the mock simulates Set/Reset in memory.
- Persisted non-sensitive UI preferences (last interface, timeout,
  ResponseDelayFactor, VLAN, rate limit, capture bound, report directory, DCP
  filter) in a versioned config file. No credentials or device values.

Additional DCP capabilities:
- Identify filtered by exact NameOfStation (one `02/02` block, case-sensitive)
  and unicast Identify to a selected MAC.
- Repeated Identify monitoring at a user-chosen interval (minimum 1 s, still
  rate-limited) with added/removed/changed-device detection for NameOfStation,
  IP parameters, role, IDs, alias, instance and advertised options. Read-only;
  one ordinary Identify per cycle and no background scanning.
- 802.1Q VLAN tagging for requests and capture, with stacked tags reported.
- ResponseDelayFactor-based timeout extension for slow device stacks.
- Read-only Get presets for identity, IP, name, Device ID, role, options, alias,
  instance, OEM ID and device-initiative blocks, plus explicit DCP block-error
  decoding.
- DCP Signal (`05/03`, SignalValue `0x0100`) as a plain identification
  action: one unicast frame, rate-limited, never retried, no confirmation.
- Legacy FactoryReset (`05/05`, BlockQualifier `0x0000`, full reset, no mode
  field) behind the same guarded path as ResetToFactorySettings modes
  1/2/3/4/8/9. The qualifier table is verified by Wireshark and p-net; the
  erased scope remains device-specific (p-net resets application and
  communication data for every mode ≥ 3).

Diagnostics, capture and reporting:
- Bounded passive capture with DCP filtering, decoded blocks, hex inspection,
  a structured event log and a transaction log.
- PCAP export and offline PCAP analysis (`dcp-cli pcap`).
- JSON (schema version 2; metadata = application/version) and dependency-free
  escaped HTML reports, including before/after observations, timing, warnings
  and known limitations.
- Request rate limiter shared by all reads and writes; late, duplicate,
  unrelated and truncated responses handled explicitly.
- 22-case functional test catalogue with a functional ID namespace
  (`env.*`, `parser.*`, `protocol.*`, `validation.*`, `write.*`); read-only by
  default, with state-changing tests only in the declared-device suites.

Quality gates:
- `uv run ruff check src tests tools` (explicit rule selection), `uv run mypy`
  and `uv run pytest` (offscreen Qt) are the required gates.
- Verified on an isolated lab segment without recording vendor, model, MAC, IP
  or station identifiers; see `HANDOFF.md`.
