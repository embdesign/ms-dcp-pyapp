# DCP Studio

A maintainable desktop application for **PROFINET DCP** device discovery,
passive decoding, configuration, reset testing, and functional testing.

Built with **Python 3.11+**, **PySide6**, **Scapy 2.8.0**, **uv**, and
`pyproject.toml`. Runs natively on Linux and Windows; no Docker required.

> **The delivered build implements the full documented capability set.** It
> enumerates interfaces, passively decodes DCP, performs multicast/unicast
> **Identify** and **Get**, and provides **Set NameOfStation**, **Set IP
> parameters**, and **ResetToFactorySettings** variants. Every state-changing
> operation requires an explicit confirmation (per operation in the
> Configuration/Reset tabs and the CLI; once per run for the declared device
> under test in the Test Runner), fresh target revalidation, and never retries
> automatically. No batch or broadcast path exists.

![DCP Studio main window: Interfaces & Discovery tab with interface list,
Identify discovery controls and the discovered-device
table](docs/pics/dcp_studio.png)

---

## What it does

- Enumerates local interfaces: name, MAC, IPv4/IPv6, link state, loopback/virtual.
- Requires an explicit interface selection; a **Demo (mock)** interface is
  available for exploration without hardware or privileges.
- Uses EtherType `0x8892` and distinguishes DCP (`FrameID 0xFEFC…0xFEFF`) from
  other PROFINET traffic.
- Sends standards-correct DCP Identify-All requests, or a filtered Identify for
  one exact NameOfStation (one request per user action), and correlates
  responses by **Xid + ServiceID + response type + target**.
- Shows MAC, NameOfStation, IP/mask/gateway, Vendor ID/Device ID, role,
  advertised DCP options, interface, and last-seen UTC.
- Deduplicates by `(interface, MAC)` and merges partial responses.
- **Monitors the segment** by repeating Identify at a configurable interval and
  reporting added/removed devices and changes to NameOfStation, IP parameters,
  device IDs, role, alias, instance and advertised DCP options. Read-only and
  user-started; each cycle is one ordinary Identify transaction.
- Preserves unknown blocks; handles truncated/malformed frames defensively.
- Performs read-only **Get** reads for identity, IP, name, Device ID, role,
  options, alias, instance, OEM ID, and device initiative blocks, with explicit
  DCP block-error reporting.
- Performs **Set NameOfStation** and **Set IP parameters** with
  temporary/permanent BlockQualifier selection and a read-back Get.
- Performs **ResetToFactorySettings** modes 1, 2, 4 and 8, and the older
  **legacy FactoryReset** (`05/05`, no mode field, full reset); every reset
  requires an explicit confirmation. Modes 3 and 9
  remain disabled because their semantics were not verified.
- **Signals one selected device** (Control/Signal `05/03`, SignalValue `0x0100`)
  so its identification LED flashes. Signal stores nothing and interrupts
  nothing, so it is **not** a state-changing operation: it needs no
  confirmation, but it is still one unicast frame with no retry.
- Provides structured logs, decoded block view, hex inspection, PCAP export and
  offline PCAP analysis.
- Exports JSON and HTML reports with UTC timestamps, transaction identifiers,
  test outcomes, before/after observations, warnings, and known limitations.
  Report JSON uses schema version 2; `metadata` carries application and version.
- Offers the same services and safety gates through a headless command line
  (`dcp-cli`), including JSON output for automation.
- Includes a mock DCP responder that simulates Set/Reset in memory, plus
  synthetic offline fixtures for tests.

It does **not** implement PROFINET cyclic IO, controller commissioning, DCE-RPC/
CM, firmware flashing, DHCP, or batch/broadcast state changes.

Within DCP itself the omissions are deliberate and recorded in the support
matrix: Hello is decoded but never sent, Set Full IP suite (`01/03`, DNS) and the
DHCP option (`03/xx`) are not transmitted, Control Start/Stop multi-block
transactions (`05/01`/`05/02`) are not used, and reset modes 3 and 9 are refused
because their semantics were not verified. Get accepts arbitrary
Option/SubOption selectors through the codec and `dcp-cli get --selector`; the
GUI exposes presets only. Monitoring is user-started polling: it repeats the
normal Identify request at a configured interval (minimum 1 s, still subject to
the shared request limiter) and stops when the operator stops it or the cycle
count is reached. It has no alerting, no history beyond the current run and no
background scanning.

See:

- [`PLAN.md`](PLAN.md) — architecture, verified dependencies, safety model.
- [`docs/references.md`](docs/references.md) — protocol verification record.
- [`docs/protocol-support-matrix.md`](docs/protocol-support-matrix.md) — what is
  implemented, disabled, unverified, or out of scope.
- [`docs/dcp-wire-format.md`](docs/dcp-wire-format.md) — byte layouts/examples.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — permissions, Npcap,
  interfaces, VLANs, timeouts.
- [`docs/lab-integration-tests.md`](docs/lab-integration-tests.md) — isolated-lab
  test procedure.

---

## Install and run with uv

### Linux

```bash
git clone <your-repo-url>
cd ms-dcp-pyapp

uv sync                 # creates .venv, installs pinned deps
uv run dcp-studio
```

Raw Layer-2 capture/send requires root or `CAP_NET_RAW`:

```bash
sudo -E uv run dcp-studio
```

If the GUI reports **“Capture may fail. Not ready: CAP_NET_RAW is not present.”**,
that is the readiness check identifying a real permission limitation, not an
application crash. Use `sudo -E`, grant `CAP_NET_RAW` to a dedicated interpreter
copy, or select the Demo (mock) interface. Full diagnosis and commands:
[`docs/troubleshooting.md`](docs/troubleshooting.md#1-linux-missing-raw-packet-permissions).

`-E` preserves the environment so `uv` uses the project virtualenv. For a
non-root setup, prefer a dedicated interpreter copy with capabilities rather
than modifying a shared system Python; see
[`docs/troubleshooting.md`](docs/troubleshooting.md#1-linux-missing-raw-packet-permissions).

### Windows

1. Install Python 3.11+ and [uv](https://docs.astral.sh/uv/).
2. Install **Npcap** from <https://npcap.com/>. Enable
   **WinPcap API-compatible Mode** unless policy forbids it.
3. Open an **elevated** terminal (Run as administrator):

```powershell
uv sync
uv run dcp-studio
```

Scapy lists Npcap adapters either by friendly name (`Ethernet`) or by NPF device
path (`\Device\NPF_{GUID}`). Both identify the same NIC. See
[`docs/troubleshooting.md`](docs/troubleshooting.md#2-windows-npcap--administrator).

### Prebuilt bundles (no Python required)

GitHub Actions builds a Windows and a Linux bundle on every push to `main`; a
`v*` tag attaches them to the GitHub Release. Unpack an archive and run the
executable inside — **Python and `uv` are not needed on the target machine**:

| Archive | Contents |
|---|---|
| `dcp-studio-windows-x64.zip`, `dcp-studio-linux-x64.zip` | desktop application (`dcp-studio[.exe]`) |
| `dcp-cli-windows-x64.zip`, `dcp-cli-linux-x64.zip` | headless CLI (`dcp-cli[.exe]`) |

Packaging removes the Python setup, not the platform requirements: **Npcap** is
still needed on Windows, and a real interface still needs Administrator or
`CAP_NET_RAW`. The `demo0` mock works unelevated. The Windows binaries are
unsigned, so SmartScreen warns on first launch. Build them yourself with the
specs in [`packaging/`](packaging/README.md).

### Demo without hardware

Select **`demo0 — Demo (mock) — offline simulated PROFINET segment`** in the
interface table, press **Start capture**, then **Discover**. Three simulated
devices respond. Select a device and use **Get blocks** to exercise read-only
Get. Configuration and reset operations are simulated in memory by the mock,
so the write UI and confirmation workflow can be exercised without hardware.

### Command line interface

The GUI remains the default (`dcp-studio` or `python -m dcpstudio`). The same
build also installs `dcp-cli`; `python -m dcpstudio COMMAND` dispatches to it.
The CLI uses the same services, codec, operations catalogue and safety gate as
the GUI; it adds no wire behaviour of its own. `-i demo` selects the offline
mock interface, which is also the default.

```bash
uv run dcp-cli interfaces
uv run dcp-cli interfaces --readiness
uv run dcp-cli discover -i demo --timeout 2
uv run dcp-cli inventory -i demo --csv inventory.csv --plan plan.csv --strict
uv run dcp-cli monitor -i demo --interval 5 --cycles 3
uv run dcp-cli get -i demo --mac 02:00:00:00:00:11 --preset identity
uv run dcp-cli signal -i demo --mac 02:00:00:00:00:11
uv run dcp-cli tests -i demo --list
uv run dcp-cli tests -i demo --select parser.fixture_decode
uv run dcp-cli pcap capture.pcap --dcp-only
```

Read-only commands (`interfaces`, `discover`, `inventory`, `monitor`, `get`,
`pcap`) never
change equipment. `inventory` writes an as-found CSV (MAC, name, IP suite,
IDs, role, options, interface, last seen) and can compare it with a plan CSV
(`mac`, `name_of_station`, `ip_address`, `subnet_mask`, `gateway`; aliases such
as `name`/`ip` accepted). `--strict` turns any plan finding into exit code 1. `signal` is the identification action: one unicast frame,
rate-limited, never retried. `set-name`, `set-ip` and `reset` require **one**
`--confirm` flag that covers authorization and the safe-maintenance state:

```bash
uv run dcp-cli set-name -i enp0s8 --mac 02:00:00:00:00:11 \
  --name line-02.conveyor --persistence permanent --confirm
uv run dcp-cli set-ip -i enp0s8 --mac 02:00:00:00:00:11 \
  --ip 192.168.20.11 --mask 255.255.255.0 --gateway 192.168.20.1 --confirm
uv run dcp-cli reset -i enp0s8 --mac 02:00:00:00:00:11 --mode 8 --confirm
```

Without `--confirm` the command prints the operation parameters and
consequences, refuses, and transmits nothing. At most one state-changing
operation runs per invocation; there is no batch or broadcast path. A
state-changing command first performs one read-only Identify to build the
confirmation and revalidates the target again inside `WriteService` immediately
before the single Set/Reset frame; if the device ignores the unicast form, the
revalidation falls back once to a NameOfStation-filtered multicast Identify and
still requires the target MAC to match. `tests` runs the read-only checks by
default; pass `--include-writes --confirm --mac MAC` (plus `--name`,
`--ip/--mask` or `--reset-mode`) to run the `write.*` cases too.

`--json` keeps stdout machine-readable (progress, operation text and report
paths go to stderr). `--report PATH` writes the same JSON or escaped HTML report
as the GUI (`.html`/`.htm` selects HTML). Exit codes are `0` success, `1` error
or refusal, and `2` inconclusive/outcome unknown (no matching response).

---

## Using the application

| Tab | Current behaviour |
|---|---|
| **Interfaces & Discovery** | Interface table, readiness/permission diagnosis, capture start/stop, timeout/ResponseDelayFactor/VLAN, optional NameOfStation filter, Identify discovery, device table with client-side search/uncommissioned filter and sorting, duplicate NameOfStation/IP warnings, inventory CSV export and plan-CSV comparison |
| **Monitor** | Repeated read-only Identify at a configurable interval with added/removed/changed-device detection (NameOfStation, IP, role, IDs, alias, options) |
| **Device Details** | Identity summary, per-block decode, raw hex, copy MAC/JSON, read-only unicast Identify, read-only **Get blocks** presets, and **Signal device (flash LED)** — one plain `05/03` frame |
| **Configuration** | NameOfStation and IPv4 Set operations with temporary/permanent qualifier, validation, per-operation confirmation, fresh target revalidation, and read-back verification |
| **Reset** | ResetToFactorySettings modes 1, 2, 4 and 8 with the documented wire qualifier, plus the legacy FactoryReset (`05/05`, full reset, no mode field); per-operation confirmation and an optional read-only post-check |
| **Test Runner** | Tests grouped by category (environment, offline parser/transactions/validation, live DCP, state-changing). Pick the device under test, then run the **device validation suite** (read-only checks plus one Set Name, one Set IP and one Reset) or the **full validation suite**; read-only presets and per-test selection are available too. The DUT selection plus the run button is the single authorization for the suite; every frame is sent once, revalidated and read back |
| **Packet Capture** | Live/offline frame list, DCP filter, hex detail, PCAP export/import |
| **Logs & Reports** | Structured event log, transaction log, session summary, JSON/HTML export |

### Safety posture

- Default operation is passive capture plus user-triggered reads.
- No automatic retries for any request, including Set and Reset.
- **Cancel** before transmission prevents the frame. Cancelling after
  transmission does not undo it; the outcome is reported as unknown and must be
  checked by discovery.
- No continuous scanning; repeated discovery is an explicit bounded test
  (3 requests, rate-limited).
- A missing response is **outcome unknown**, never proof that a device is absent
  or that an operation failed.
- Every Set/Reset requires explicit authorization, safe-maintenance confirmation,
  and a fresh Identify revalidation immediately before transmission: unicast
  first, and only for a device that ignores it a single NameOfStation-filtered
  multicast Identify whose response must still carry the target MAC. There is
  no separate arming step to remember. **Signal is the exception**:
  it changes no stored configuration, so it is a plain user-triggered action —
  still exactly one unicast frame, rate-limited, never retried.
- Name/IP writes perform one read-only read-back Get. Reset acknowledgements are
  not treated as proof of completion; the post-check polls one read-only
  Identify for a bounded, cancellable window and proves reachability only.
- There is no batch, broadcast, automatic rollback, or automatic retry path.
- Use an isolated lab network for hardware tests.

---

## Tests and fixtures

```bash
uv run pytest
uv run pytest --cov=dcpstudio --cov-report=term-missing
```

The suite covers:

- byte-exact Identify/Get/Set/Reset encoding, VLAN, Xid, block padding;
- Identify/Get decoding, empty names/IP, roles, options, unknown blocks;
- truncated, bad-length, non-DCP, and random-byte defensive parsing;
- discovery dedupe, NameOfStation-filtered discovery, wrong-Xid/unrelated
  responses, late responses, timeouts, cancellation, rate limiting;
- duplicate NameOfStation/IP detection (`protocol.address_conflicts`);
- inventory CSV export and plan comparison (MAC/name/IP suite, exact match,
  missing/unexpected/ambiguous findings);
- unicast Identify and before/after identity comparison (mock);
- live read-only Get, offline Get request/response decode, and all documented
  block errors;
- Name/IP Set with temporary/permanent qualifiers, read-back
  verification, rejection, timeout, authorization and revalidation gates,
  including the NameOfStation-filtered multicast revalidation fallback;
- ResetToFactorySettings acknowledgement and the bounded, polling post-check;
- PCAP roundtrip and timestamp preservation;
- JSON/HTML report content, write operations, schema version 2 metadata and HTML escaping;
- safety gate, and the Signal path (`05/03`);
- headless CLI commands, exit codes, JSON output and report writing;
- station-name/IP validation;
- GUI smoke test (offscreen), mock discovery, and write integration.

Fixtures are synthetic and documented in
[`tests/fixtures/PROVENANCE.md`](tests/fixtures/PROVENANCE.md). Regenerate with:

```bash
uv run python tools/make_fixtures.py
```

Offline tests never send frames to live equipment.

---

## Project layout

```
src/dcpstudio/
  __init__.py           application name, phase and installed version
  constants.py          verified DCP values (no guesses)
  codec.py              pure encode/decode including Set, Signal and reset builders
  model.py              frames, blocks, devices, results, UTC helpers
  outcomes.py           typed outcome vocabulary and display texts
  html_render.py        one escaping/table-markup path for reports and GUI summaries
  operations.py         operation catalogue (confirmation text + qualifier)
  validation.py         PROFINET name / IPv4 suite rules
  interfaces.py         domain interface/readiness descriptions and the mock interface
  session.py            single composition root for the transport and services
  transport/            interface enumeration, Scapy transport and transport factory
  services/             rate limit, capture, correlation, discovery, Get, Signal and write
  testrunner/           test catalogue (cases.py), runner engine and handlers/
  pcap_io.py            classic Ethernet PCAP reader/writer
  reporting.py          JSON and escaped HTML reports
  inventory.py          as-found CSV inventory and plan comparison (pure)
  safety.py             per-operation confirmation and authorization guard
  mock.py               offline mock devices; simulates Set/Reset in memory
  fixtures.py           synthetic offline frames
  cli.py                headless CLI over the same services and safety gate
  config.py             non-sensitive UI preferences
  logging_setup.py      thread-safe structured event log
  utils.py              hexdump / JSON helper functions
  gui/                  eight-tab PySide6 UI: app, controller, workers, presentation, tabs/
tests/                  unit, integration-with-mock, GUI smoke and CLI tests
docs/                   protocol, references, lab, troubleshooting, fixtures
```

---

## Known limitations

- Read-only operation has been exercised against real hardware on an isolated
  lab segment: Identify-All, unicast Identify, read-only Get and the read-only
  functional tests.
- **State-changing paths were validated on one lab device** (vendor, model and
  identifiers withheld): Set NameOfStation and Set IP were acknowledged and read
  back with both temporary (`0x0000`) and permanent (`0x0001`) BlockQualifier;
  `ResetToFactorySettings` modes 2 and 8 and the legacy FactoryReset (`05/05`)
  were acknowledged (the device reboots), while modes 1 and 4 were **rejected by
  that device with DCP block error `0x02`**. Device support remains
  vendor-dependent; use the isolated-lab procedure for your own hardware.
- Windows/Npcap behaviour is implemented from documented Scapy APIs but was not
  executable on the Linux host used to build and test the project.
- DCP is link-local; it does not cross routers and is bounded by VLANs and
  multicast filtering.
- State-changing operations revalidate the target with a fresh **read-only**
  Identify. When a device ignores unicast Identify, the revalidation falls back
  once to a NameOfStation-filtered multicast Identify and requires the target
  MAC to match. A device that answers neither form still cannot be configured or
  reset; the outcome is `target_unverified` and nothing is transmitted.
- DCP discovery cannot prove an IP address is unused.
- A missing Get response is not proof that a device does not support the block;
  a device may also return an explicit DCP block error.
- Unknown/vendor-specific blocks are displayed but not interpreted.
- Name/IP Set, reset modes 1/2/4/8 and legacy FactoryReset (`05/05`) are
  implemented; modes 3 and 9 remain disabled because their semantics were not
  verified on hardware. Device support and erased scope remain vendor-dependent.
- Signal (`05/03`) is implemented as an identification aid, not a state change:
  it changes no configuration, and a device may or may not flash its LED. The
  acknowledgement is not proof that the LED was visible, so the on-screen result
  is deliberately short — "signal acknowledged" plus block error and round-trip
  time. The full record (Xid, frame hex, verification wording) stays in the
  event log.
- Monitoring repeats Identify: it reports only the fields carried by Identify
  responses, has no alerting, thresholds or history beyond the current run, and
  a cycle with no answer is `no_responses`/`outcome_unknown`, not proof that the
  device is absent.
- Reports are operational evidence, **not** PROFINET conformance certificates.
- The inventory is an **as-found** snapshot of DCP-visible identity only. It does
  not prove that a planned IP is free, and a plan comparison cannot see a device
  that does not answer Identify.

Captures and reports contain sensitive identifiers (MAC, station name, IP,
vendor/device IDs). Handle them accordingly.

## License

MIT. See [`LICENSE`](LICENSE).

