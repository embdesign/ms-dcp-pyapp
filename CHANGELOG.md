# Changelog

All notable changes to **DCP Studio** (`dcpstudio`) are documented in this
file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Small-screen layout controls.** The window minimum is now 900 × 600 px (was
  1100 × 760) and the initial size is clamped to the available screen instead of
  always opening at 1440 × 940. A new **Edit** menu toggles the title header, the
  advanced Identify filter fields, the static notice at the top of each tab and a
  compact spacing stylesheet; all four options are persisted in `config.json`
  (`show_app_header`, `show_identify_filters`, `show_tab_notices`,
  `compact_spacing`). Group-box titles are unchanged. Only static notices can be
  hidden (`banner(..., notice=True)`); a banner whose text a run fills in
  (`monitor_notes_label`) and every status/readiness/result label stay visible.
  While the filter fields are hidden they are **not** applied (the Discover
  tooltip says Identify-All is sent), so hiding can never change a frame
  silently. The Identify forms wrap their labels above the fields on a narrow
  pane, the packet-capture BPF expression moved to the statistics row so it is
  no longer squeezed, and a 900 × 600 window with the header, filters, notices and
  spacing compacted shows the whole Identify section without a scrollbar (the
  notices alone return 44 px per tab).
- **Custom Get selectors in the GUI.** The Device Details tab has a **Custom
  selectors** field next to the preset combo, so any `Option/Sub-option` block
  (`0x03/0x0c`, `0xff/0x01`, repeatable, comma separated) can be read from the
  selected device. The preset remains the default; explicit entries win over it,
  are validated before a request is prepared, and appear as a name or as raw hex
  in the result and the event log. The parser and resolver (`parse_selector`,
  `parse_selectors`, `choose_selectors`) live in `services/get.py` and are shared
  with `dcp-cli get --selector`. DHCP sub-options now have display names
  (`03/0c` host name … `03/ff` control).
- **Multi-block Identify filters.** Besides NameOfStation, an Identify request
  can filter by Alias (`02/06`), vendor/type (`02/01`), device ID (`02/03`),
  device role (`02/04`) and MAC (`01/01`). Conditions are sent in the
  IEC/p-net order (name, alias, then the rest) and every one must match. The
  Discovery tab gained the fields, `dcp-cli discover`/`inventory` gained
  `--alias`, `--vendor`, `--vendor-id`/`--device-id`, `--role` and
  `--filter-mac`.
- **DNS and DHCP state in the read-only views.** Device Details, the device JSON
  and the HTML report now show the DNS servers of an `01/03` block and the DHCP
  control of an `03/ff` block. A new `network` Get preset (`dcp-cli get
  --selector 1/3 --selector 3/255`) reads both, and the diagnostics preset
  includes them.
- **Set Full IP suite (`01/03`) and DHCP control (`03/ff`).** The Configuration
  tab and `dcp-cli set-ip-suite` set IP/mask/gateway plus up to four DNS servers
  in one guarded block; `dcp-cli set-dhcp` / the Configuration tab set the DHCP
  on/off control. Both use the temporary/permanent qualifier where defined,
  a fresh revalidation, one frame and a read-back Get. The value layouts follow
  the Wireshark `pn_dcp` dissection (and RFC 2132 for the DHCP option codes),
  not a device stack that leaves them unimplemented; device support varies.
- **Reset modes 3 and 9 are transmitted.** `ResetToFactorySettings` now covers
  every mode of the DCP reset table (1, 2, 3, 4, 8, 9), behind the same
  per-operation confirmation, revalidation and post-check. Wireshark defines the
  qualifier values (`0x0006` / `0x0012`) and p-net resets application **and**
  communication data for every `reset_mode >= 3`; the erased scope remains
  vendor-specific and is stated in the confirmation text.
- **Revalidation fallback for unicast-deaf devices.** When a target ignores the
  unicast Identify, `WriteService` retries the read-only revalidation once with a
  NameOfStation-filtered multicast Identify and still requires the target MAC
  (and the full identity text) to match. Such writes are logged as
  `safety.revalidation_fallback` and carry a warning in the result. A target
  that answers neither form is still `target_unverified` and nothing is sent.
- **Duplicate NameOfStation/IP detection.** Discovery now warns when two devices
  advertise the same NameOfStation or IPv4 parameter, and the new read-only test
  `protocol.address_conflicts` fails the run when it is present.
- **Bounded post-reset re-check.** The read-only post-check polls the target
  Identify inside a cancellable window (default 40 s, configurable) instead of a
  single
  attempt, and falls back to an unfiltered multicast Identify for the same MAC
  when the reset cleared the station name.
- **Device inventory and plan comparison.** `dcp-cli inventory` and the Discovery
  tab export an as-found CSV and compare it with a plan CSV
  (`mac`/`name_of_station`/`ip_address`/`subnet_mask`/`gateway`, aliases
  accepted). Findings are `missing_device`, `unexpected_device`,
  `ambiguous_match` and per-field mismatches; `--strict` exits 1 on findings.
  Pure helpers live in `inventory.py`.
- **Device-table filtering.** The Discovery tab has a client-side search box,
  an "only uncommissioned" view and column sorting. The NameOfStation filter
  that shapes the Identify request is unchanged.
- **Configurable post-check window.** `AppConfig.post_check_window_s`, a Reset-tab
  spin box and `--post-check-window SECONDS` replace the hard-coded value.

### Fixed

- **Stale DHCP limitation in the report.** `KNOWN_LIMITATIONS` said DHCP was not
  implemented; it now names DHCP *option* assignment (option codes 12…97) and
  states that the DHCP control (`03/ff`) is read and can be set.
- **Discovery tab shrinking.** The Identify section no longer clips its
  Discover button and summary when the window is small: its content sits in an
  internal scroll area (section 2 scrolls, the interface and device tables keep
  their size), the capture-permission text moved into the interface section, and
  the splitter can no longer collapse a pane. At the default window size the
  section fits without a scrollbar.
- **Wire-conformance guards found by the specification audit (2026-11-21).**
  `build_get_request` now rejects multicast/broadcast destinations (Get is a
  unicast transaction), and `build_identify_request` accepts only the DCP
  multicast MAC or a single device MAC. The parser now warns when a Set block
  is too short to carry its mandatory BlockQualifier and when the reserved
  header field is non-zero outside Identify requests.

### Changed

- **No session-wide "configuration mode".** Set NameStation/IP and Reset are
  reachable as soon as one target is selected; a single per-operation
  confirmation (GUI dialog or `--confirm`) remains the gate, followed by the
  same fresh unicast-Identify revalidation, single send and read-back. The
  Configuration tab, status bar, About box, reports, Test Runner text and all
  documentation no longer describe the tool as read-only-by-default.
- `dcp-cli set-name` / `set-ip` / `reset` now require only `--confirm`
  (`--enable-configuration` and `--safe-maintenance` were removed).
- `dcp-cli tests` can run the `write.*` cases with the new
  `--include-writes --confirm --mac` flags; `--name`, `--ip`/`--mask`,
  `--gateway`, `--persistence` and `--reset-mode` supply the test values.

## [0.1.1] - 2026-11-19

### Added

- **Monitor tab and `dcp-cli monitor`** — user-started repeated Identify at a
  configurable interval (minimum 1 s, still subject to the shared request
  limiter) with change detection for added/removed devices and changed
  NameOfStation, IP parameters, role, IDs, alias, instance and advertised DCP
  options. Read-only: each cycle is one ordinary Identify transaction, the loop
  lives in `services/monitor.py`, and the diff/vocabulary in the pure
  `monitor.py`.

### Changed

- Documentation states the intentional DCP scope gaps explicitly: Hello is
  decoded but never sent, Set Full IP suite (`01/03`, DNS) and the DHCP option
  (`03/xx`) are not transmitted, Control Start/Stop multi-block transactions are
  not used, reset modes 3 and 9 stay refused, Get accepts arbitrary selectors
  only through the codec/CLI, and monitoring is user-started polling without
  alerting or background scanning (`README.md`, `docs/protocol-support-matrix.md`).
- `HANDOFF.md` verification numbers refreshed (254 tests) and the rebuilt
  `0.1.1` artifacts recorded.

### Fixed

- GUI tab labels show their literal ampersand again: `Interfaces & Discovery`
  and `Logs & Reports` were rendered as `Interfaces _Discovery` / `Logs
  _Reports` because Qt consumed the single `&` as a mnemonic marker.
- The hex dumps (Packet Capture *Frame detail*, Device Details *Raw response*)
  are column-aligned again. The window style sheet assigns a proportional
  `font-family` to every widget, which silently overrode the monospace font
  set on the text panels; they now override it with a widget-level rule.

## [0.1.0] - 2026-11-14

First released version. Desktop application and headless CLI for PROFINET DCP
discovery, passive decoding, guarded configuration, reset testing and
functional testing.

### Added

- **Interface handling** — enumeration via Scapy (`name`, `MAC`, IPv4/IPv6,
  flags, Linux link state), explicit single-interface selection, interface
  readiness/permission diagnosis (`CAP_NET_RAW` on Linux, Npcap on Windows) and
  an offline `demo`/`demo0` mock interface that needs no hardware or privileges.
- **DCP framing** — hand-written `struct` encoder/decoder for EtherType
  `0x8892` and FrameIDs `0xFEFC…0xFEFF` (no Scapy DCP layer exists), single
  802.1Q VLAN tag, byte-exact Identify/Get/Set/Signal/Reset builders.
- **Discovery** — Identify-All, unicast Identify, and Identify filtered by one
  exact NameOfStation; correlation by Xid + ServiceID + response type + target;
  deduplication by `(interface, MAC)` with merging of partial responses;
  configurable timeout and ResponseDelayFactor.
- **Defensive parsing** — unknown and vendor-specific blocks preserved without
  interpretation, truncated/malformed frames reported as warnings instead of
  exceptions, bounded decode loops.
- **Read-only Get** — identity, IP parameters, NameOfStation, Device ID, role,
  options, alias, instance, OEM ID and device-initiative blocks, with explicit
  DCP block-error reporting (codes `0x00`–`0x07`) and GUI presets.
- **Guarded writes** — Set NameOfStation (`02/02`) and Set IP parameters
  (`01/02`, 12-byte suite) with temporary/permanent BlockQualifier, PROFINET
  name/IP validation, per-operation confirmation and a read-back Get.
- **Guarded reset** — ResetToFactorySettings (`05/06`) modes 1, 2, 4 and 8, plus
  the legacy FactoryReset (`05/05`, no mode field, full reset). Modes 3 and 9
  are refused by the encoder because their semantics are unverified.
- **Device Signal** — Control/Signal `05/03` with SignalValue `0x0100` to flash
  a device's identification LED; deliberately unguarded (it stores and
  interrupts nothing) but still one unicast frame, rate-limited, never retried.
- **Test runner** — functional test catalogue with `env.*`, `parser.*`,
  `protocol.*`, `validation.*` and `write.*` IDs; read-only tests by default and
  optional guarded state-changing tests, at most one per run, each with its own
  confirmation.
- **Packet capture** — live capture in a Scapy `AsyncSniffer` thread and offline
  analysis; DCP filter, decoded block view, hex inspection, classic PCAP
  export/import with timestamp preservation.
- **Reports** — JSON (schema version 2, `metadata` carries application and
  version) and dependency-free escaped HTML, with UTC timestamps, transaction
  identifiers, test outcomes, before/after observations, warnings and known
  limitations.
- **Headless CLI** (`dcp-cli`, also `python -m dcpstudio COMMAND`) — `interfaces`,
  `discover`, `get`, `signal`, `set-name`, `set-ip`, `reset`, `tests` and `pcap`
  over the same services, codec, operations catalogue and safety gate as the
  GUI. `--json` keeps stdout machine-readable, `--report PATH` writes a JSON or
  HTML report, exit codes `0` success / `1` error or refusal /
  `2` inconclusive (outcome unknown).
- **Offline tooling** — mock DCP responder that simulates Set/Reset in memory,
  synthetic frame fixtures with documented provenance
  (`tests/fixtures/PROVENANCE.md`) and `tools/make_fixtures.py`.
- **GUI** — seven tabs (Interfaces & Discovery, Device Details, Configuration,
  Reset, Test Runner, Packet Capture, Logs & Reports) in PySide6; all blocking
  I/O runs in `QThread` workers, never on the GUI thread.

### Changed

- Version is resolved from installed distribution metadata
  (`importlib.metadata`); `pyproject.toml` remains the single source of truth
  and is covered by `tests/test_version.py`.
- Guarded-operation text and parameters live once in `operations.py` and are
  consumed by the GUI, the CLI and the test runner; the wire BlockQualifier
  comes from `codec.request_qualifier()`.

### Security

- Layered safety model: configuration mode off by default, explicit
  authorization plus safe-maintenance confirmation for every Set and Reset,
  fresh unicast Identify revalidation immediately before the single frame.
- No automatic retry, no rollback, no batch, no broadcast and no multi-device
  path; unicast targets only.
- A timeout is reported as `outcome_unknown`, never as "failed" or "absent"; an
  acknowledgement is never treated as proof of persistence or reset completion.

### Packaging

- PyInstaller one-folder bundles from `packaging/*.spec` for Linux x64 and
  Windows x64: `dcp-studio` (GUI) and `dcp-cli` (headless), built by
  `.github/workflows/package.yml` and attached to a GitHub Release by
  `release.yml` on a `v*` tag. Python and `uv` are not required on the target
  machine; Npcap is still required on Windows and raw L2 access still requires
  Administrator or `CAP_NET_RAW`.
- Windows bundles are unsigned.

### Tests

- 181 tests (codec, parsing, discovery, services, safety, CLI, reporting,
  PCAP, offscreen GUI smoke and orchestration); `ruff` lint gate clean.

### Known limitations

- Read-only operation was validated against real hardware on an isolated lab
  segment. State-changing paths were validated on one lab device only; device
  support remains vendor-dependent (`ResetToFactorySettings` modes 1 and 4 were
  rejected by that device with block error `0x02` while modes 2, 8 and legacy
  `05/05` were acknowledged).
- Windows/Npcap code paths are implemented from documented Scapy APIs but were
  not executable on the Linux host used to build and test the project.
- Devices that do not answer unicast Identify cannot be configured or reset,
  even if they answer multicast discovery.
- DCP is link-local; it does not cross routers and is bounded by VLANs and
  multicast filtering. Discovery cannot prove an IP address is unused.
- Reports are operational evidence, not PROFINET conformance certificates.
- Out of scope: PROFINET cyclic IO/RT, PTCP, MRP, LLDP topology, controller
  commissioning, DCE-RPC/CM, firmware flashing and DHCP.
