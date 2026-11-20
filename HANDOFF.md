# Task Handoff

Project: `dcp-studio` 0.1.1 (package `dcpstudio`, folder `ms-dcp-pyapp`).
Last updated: 2026-11-19.

> All statements below are based on direct inspection of the files as they
> exist on disk. Take a backup archive before bulk edits and do not commit
> without operator authorization.

## Goal and acceptance criteria

**Deliverable (from `PROMPT.md`):** a maintainable PROFINET DCP desktop
application — interface enumeration, Identify discovery, passive decoding,
read-only Get, unguarded LED Signal, guarded Set NameOfStation / IP, verified
ResetToFactorySettings variants plus legacy FactoryReset, functional test
runner, capture/PCAP, JSON+HTML reporting, Windows/Linux docs, mock responder,
offline fixtures with provenance, lab procedure, support matrix,
troubleshooting, and a headless CLI — never implementing an unverified
destructive operation.

Acceptance = phases 1–4 implemented; every state-changing path gated
(per-operation confirmation, fresh target revalidation, no
retry/batch/broadcast); unverified operations refused rather than guessed;
tests and docs present and consistent.

## Current status

Complete. The suite passes, the lint gate is clean, the packaging
artifacts were rebuilt, and the read-only plus write paths were validated on
an isolated lab segment. No deferred work remains.

## Implemented changes

Documentation-only pass on 2026-11-14; no source, dependency, wire-format or
config change was made.

- `PROMPT.md` — added §10 *Implemented in the delivered build* covering the
  headless CLI, unguarded Signal, legacy FactoryReset, VLAN tagging,
  ResponseDelayFactor, preferences, reports and quality gates.
- `PLAN.md` — retitled *Architecture and Implementation Record*; updated the
  status/scope, architecture diagram (`SignalService`), module map (`cli.py`,
  `utils.py`, `services/signal.py`, `testrunner/cases.py`, `gui/app.py`,
  `gui/workers.py`, `gui/confirmation.py`, `gui/presentation.py`, `gui/tabs/`),
  threading, safety table, phase table and limitations.
- `AGENTS.md` — refreshed verified facts: 297 tests / ~132 s, `cli.py` as a
  consumer of `operations.py`, Signal exposed by the Device Details tab and
  `dcp-cli signal`, `dist/` rebuilt 2026-11-19 (0.1.1).
- `README.md` — removed historical wording, refreshed the project layout and
  test-coverage list, corrected the “this phase” wording.
- `HANDOFF.md` — replaced the historical session log with this handover.

Current capability summary (verified in the tree):

- Discovery: Identify-All, exact-NameOfStation-filtered Identify (`02/02`),
  unicast Identify, dedupe by `(interface, MAC)`, late/unrelated/duplicate
  handling, VLAN tagging and ResponseDelayFactor timeout extension.
- Monitor: repeated read-only Identify at a configured interval (minimum 1 s)
  with added/removed/changed-device detection for NameOfStation, IP parameters,
  role, IDs, alias, instance and advertised options; Monitor tab and
  `dcp-cli monitor`.
- Read-only Get with presets and explicit DCP block-error decoding.
- Unguarded DCP Signal (`05/03`, SignalValue `0x0100`): one unicast frame,
  rate-limited, never retried, never routed through `WriteService`.
- Set NameOfStation, Set IP, RTFS modes 1/2/4/8 and legacy FactoryReset
  (`05/05`): per-operation confirmation, fresh read-only revalidation (unicast,
  with one NameOfStation-filtered multicast fallback for devices that ignore
  unicast), one frame, read-back Get (Set) or a bounded polling post-check
  (reset).
- Duplicate NameOfStation/IP detection in discovery warnings and in the
  `protocol.address_conflicts` read-only test.
- As-found inventory CSV export and plan comparison (`dcp-cli inventory`,
  `inventory.py`, Discovery-tab buttons) plus client-side device-table
  search/uncommissioned filter/sorting.
- Configurable, persisted post-check window (`AppConfig.post_check_window_s`,
  Reset-tab spin box, `--post-check-window`).
- 22-case functional test catalogue (`env.*`, `parser.*`, `protocol.*`,
  `validation.*`, `write.*`); at most one state-changing test per run.
- Eight-tab GUI and headless `dcp-cli` (`python -m dcpstudio COMMAND`) over the
  same services, operations catalogue and safety gate; CLI exit codes 0/1/2 with
  `--json` and `--report` output.
- Passive capture, transaction log, hex inspection, PCAP export and offline
  PCAP analysis, JSON (schema v2) and escaped HTML reports.
- Demo/mock interface with three simulated devices; versioned non-sensitive UI
  preferences; explicit ruff and pytest gates.

## Decisions and rationale

- The request was documentation-only: `PROMPT.md` and `PLAN.md` had to describe
  the implemented build, and obsolete text had to be removed from `AGENTS.md`,
  `HANDOFF.md`, `PLAN.md` and `README.md`.
- Facts were re-verified against the tree before writing: 297 tests pass, the
  ruff gate is clean, PySide6 resolves to 6.12.0 and `dist/` was rebuilt on
  2026-11-19 (version 0.1.1).
- Historical narrative (resolved review items, old coverage/refactor numbers,
  superseded phase labels) was removed rather than preserved as contradictory
  task state.
- No new feature was added and no public interface was renamed.

Constraints a future agent must preserve:

- Verified constants only (`constants.py` + `docs/references.md`).
- Unicast-only guarded writes; no automatic retry, rollback, batch or broadcast.
- A timeout is `outcome_unknown`, never "failed" or "proven absent".
- An acknowledgement is never proof of persistence or reset completion.
- Reset modes 3 and 9 stay refused; legacy `05/05` stays fixed at qualifier
  `0x0000` with no selectable scope.
- Signal stays unguarded but single-frame; do not route it through
  `WriteService`.
- `fixtures.py` stays in the package: the shipped test runner uses it.

## Verification

| Check | Command / procedure | Result |
|---|---|---|
| Full suite | `QT_QPA_PLATFORM=offscreen uv run pytest` | **PASS** — 297 passed in 131.90 s |
| Lint gate | `uv run ruff check src tests tools` | **PASS** — all checks passed |
| Package artifact inspection | `.venv/bin/python -m zipfile -l dist/dcp_studio-0.1.1-py3-none-any.whl` | **PASS** — contains `dcpstudio/cli.py`, `gui/app.py`, `services/signal.py`, `entry_points.txt`. `uv build` was re-run on 2026-11-19 for version 0.1.1. |
| Sensitive-data review | manual read of all changed documents | **PASS** — lab vendor/model/MAC/IP/station identifiers remain withheld; only the synthetic examples `02:00:00:00:00:11` and `192.168.20.x` appear. |

Not verified in this pass: Windows/Npcap, other vendors' devices, power-cycle
persistence of permanent values, and GUI interaction beyond the offscreen smoke
test. The live lab run below was performed earlier on 2026-11-14 and was not
repeated.

### Lab validation record (2026-11-14)

Performed on an isolated lab segment with a dedicated NIC, using
`.venv/bin/python-raw` (`CAP_NET_RAW` present; `sudo` needs a password on this
host, so the capability-carrying interpreter is the way to run live).
**No vendor, model, MAC address, IP address or station name from that lab is
recorded here** — and none may be added. See `AGENTS.md` for that rule.

Phase 1 — read-only (no `write.*` tests selected):

| Step | Result |
|---|---|
| `enumerate_interfaces()` | mock interface, two physical NICs and `lo` enumerated |
| Readiness | `raw_socket_privileges=(True, 'CAP_NET_RAW …')`, `capture_driver_status=(True, 'Scapy raw sockets available')` |
| Identify-All (one request, 3 s) | 2 devices, 0 late, 0 unmatched; request on the wire `fefe 05 00 … 0004 ffff 0000` (BlockLength 0) — matches the documented form |
| Get (read-only) | `02/02` NameOfStation returned, RTT ~40 ms; request payload `0202` (Option/SubOption only) |
| Read-only functional tests | **17 passed, 0 failed, 0 skipped, 0 inconclusive** (`env.*`, `parser.*`, `protocol.*`, `validation.*`) |

Two devices answered: a PC-class station (device-role byte `0x0000`, i.e. no
role bit set) and one IO-Device with **NameOfStation not set**. The IO-Device
advertises `02/0a` RSI properties, `02/0b` Protocol properties and `07/05` CIM
interface — confirming the names recorded in `constants.py` and
`docs/references.md` on real hardware, not only in an offline capture.

Phase 2 — state-changing (operator authorized, "all is safe"):

Executed through the shipped `TestRunner` / `WriteService` paths with
per-operation authorization, fresh unicast revalidation,
single send and no retry. Writes targeted **only the IO-Device**; the PC-class
station received read-only frames only.

| Operation | Qualifier | Device response | Verification |
|---|---|---|---|
| Set NameOfStation (test name), **temporary** | `0x0000` | acknowledged, `blockError 0x00` | read-back Get matched |
| Set NameOfStation (same name), **permanent** | `0x0001` | acknowledged, `blockError 0x00` | read-back Get matched |
| Set IP (second free address in the lab subnet, mask `/24`, lab gateway), **temporary** | `0x0000` | acknowledged, `blockError 0x00` | read-back matched; device moved to the new address |
| Set IP (same suite), **permanent** | `0x0001` | acknowledged, `blockError 0x00` | read-back matched |
| RTFS **mode 1** (application data) | `0x0002` | **rejected, `blockError 0x02`** | not supported by this device |
| RTFS **mode 2** (communication parameters) | `0x0004` | acknowledged, `blockError 0x00`, device reboots | after reboot name/IP were cleared — reset demonstrably applied |
| RTFS **mode 4** (all except security) | `0x0008` | **rejected, `blockError 0x02`** | not supported by this device |
| RTFS **mode 8** (factory values) | `0x0010` | acknowledged, `blockError 0x00`, device reboots | temporary name/IP were erased and the device returned with its default identity |
| **Legacy FactoryReset `05/05`** | `0x0000` | acknowledged, `blockError 0x00`, device reboots | first hardware confirmation that a device accepts `05/05` |

Post-checks after each reset correctly reported `no_response` while the device
was rebooting — recorded as *outcome unknown*, not as failure, exactly as the
outcome vocabulary requires. Request frames matched the documented layouts:
`02/02 …0000|0001`, `01/02 …000e …`, `05/06 …0002|0004|0008|0010`,
`05/05 0002 0000`.

Final state after the run: the device was left with no NameOfStation and its
default address, i.e. nothing from the tests remains configured.

**Not exercised even here:** reset modes 3/9 (refused by the encoder),
power-cycle persistence of *permanent* values (no power control), and any other
vendor's device. DCP Signal (`05/03`) *was* exercised: acknowledged with
`blockError 0x00` and no confirmation dialog (`RTT` ≈ 32 ms); the LED
effect itself is not observable over DCP.

## Known issues and review findings

Verified by inspection:

1. **Device-properties sub-option `0x09` is unnamed.** The p-net mirror defines
   `PF_DCP_SUB_DEV_PROP_GATEWAY` at `0x09`, but the Wireshark dissector does not
   define it. It stays "Unknown sub-option 0x09" until an authoritative source
   resolves the disagreement.

AI review finding (not an independently verified defect): documentation
drift is checked only by review and tests, not by an automated consistency
check. Keep `README.md`, `PLAN.md`, `docs/protocol-support-matrix.md` and the
tests updated in the same change.

## Next actions

Required work: none.

Optional improvements, in priority order:

1. Resolve sub-option `0x09` against an authoritative source before naming it.
2. Re-run `uv build` after any future source change; this documentation-only
   pass did not change the package contents.
3. Re-run the isolated-lab procedure for any new device or vendor.

## How to resume

Read first, in this order:

1. `AGENTS.md` — commands, invariants, pitfalls (authoritative for day-to-day work).
2. `PROMPT.md` — the original requirements; `PLAN.md` — verified API/protocol
   facts and the architecture record.
3. `docs/protocol-support-matrix.md` — what is implemented, disabled, unverified.
4. `src/dcpstudio/safety.py` and `src/dcpstudio/services/write.py` before
   touching any state-changing path.
5. `tests/test_write_service.py`, `tests/test_gui_smoke.py`,
   `tests/test_gui_orchestration.py`, `tests/test_cli.py` — safety, widget,
   controller and CLI expectations.

For further work, start from `src/dcpstudio/operations.py`
(guarded-operation catalogue), `gui/main_window.py` (shared controller),
`gui/tabs/<tab>.py` (tab-local widgets/handlers), `gui/presentation.py`
(rendering), `testrunner/cases.py` (test catalogue) and `cli.py` (headless
adapter). Run `uv run ruff check src tests tools` and
`QT_QPA_PLATFORM=offscreen uv run pytest` before and after any change.
Make a backup archive before bulk edits.
