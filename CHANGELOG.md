# Changelog

All notable changes to **DCP Studio** (`dcpstudio`) are documented in this
file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-19

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
