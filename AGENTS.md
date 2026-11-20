# AGENTS.md — working rules for this repository

Scope: this repository (`dcp-studio` / package `dcpstudio`).
Read this before changing code. It records only facts verified in this tree.

## Project facts

- Python `>=3.11`; managed with **uv** + `pyproject.toml` (hatchling build).
- Runtime dependencies: `scapy==2.8.0` (pinned, interfaces + raw L2 I/O only),
  `PySide6>=6.8,<7` (stable QtCore/QtWidgets APIs only).
- Source layout is `src/dcpstudio/...` (no `tests/unit` vs `tests/integration`
  split; tests are flat in `tests/`).
- Domain: PROFINET **DCP** (EtherType `0x8892`, FrameIDs `0xFEFC…0xFEFF`).
  DCP framing is hand-implemented with `struct`; Scapy provides no DCP layer.

## Commands (verified)

```bash
uv sync                                     # create .venv + dev group
uv run pytest                               # full suite (offscreen Qt, 277 tests)
uv run pytest --cov=dcpstudio --cov-report=term-missing
uv run ruff check src tests tools           # configured lint gate (clean)
uv run mypy                                 # typed gate for the pure modules (clean)
uv run dcp-studio                           # launch GUI
uv run dcp-cli --help                       # headless CLI (also python -m dcpstudio COMMAND)
uv run dcp-cli interfaces                   # list interfaces ('demo'/'demo0' = offline mock)
sudo -E uv run dcp-studio                   # raw L2 capture/send on Linux
uv run python tools/make_fixtures.py        # regenerate tests/fixtures/*
```

- **Standalone bundles** are built by PyInstaller from `packaging/*.spec`
  (one folder, GUI + Qt-free CLI). CI does it in `.github/workflows/package.yml`
  (`ubuntu-22.04` + `windows-latest`) and `release.yml` attaches the zips to a
  `v*` tag. PyInstaller cannot cross-compile and the specs must stay in step with
  the entry points; `packaging/README.md` records the constraints.

- `tests/conftest.py` already sets `QT_QPA_PLATFORM=offscreen` and redirects
  `XDG_CONFIG_HOME`/`APPDATA` to a temp dir. Do not write to the real profile
  in tests.
- Linting is configured in `pyproject.toml` with an explicit rule selection
  (`ruff` dev dependency): `uv run ruff check src tests tools` is clean.
  `BLE001` is deliberately ignored because broad excepts are used at capture,
  worker and Qt-slot boundaries; do not add per-file blanket ignores.

## Architecture constraints — do not break

- `codec.py` is pure encode/decode: no I/O, no timing, no UI. Transport-agnostic.
- All raw I/O goes through the `DcpTransport` protocol
  (`transport/base.py`); `ScapyTransport`, `MockTransport` and offline fixtures
  are interchangeable behind it. Interface/readiness data types live in the
  domain module `interfaces.py`; `transport/base.py` and
  `transport/interfaces.py` re-export them for compatibility — do not move them
  back into the transport package.
- **One composition root.** `session.build_services()` / `open_session()` /
  `probe_readiness()` in `session.py` are the only places that construct a
  transport or the discovery/Get/Write/Signal/monitor services. The GUI, `cli.py` and
  `testrunner/runner.py` must not rebuild that wiring. `tests/test_layer_boundaries.py`
  enforces this and the rest of the layering; add new exceptions to its
  documented allowlist, never by loosening a rule.
- **One correlation primitive.** Response correlation goes through
  `services/correlation.py` (`PendingRequest`, `decide_frame()`,
  `wait_for_response()`, `collect_until_deadline()`). Services keep only their
  matching policy and transaction text; never reintroduce a per-service pending
  dataclass, duplicate/unmatched bookkeeping or wait loop.
- **One outcome vocabulary.** Result states, verification, post-check and
  transaction outcomes are the `StrEnum`s in `outcomes.py`, and their display
  text lives in the same module. Never assign a result-state string literal
  elsewhere; the JSON/report representation is the enum value. `TestResult.status`
  is a separate test-verdict vocabulary.
- **One HTML path.** Escaping and table markup live in `html_render.py`
  (`esc`, `cell`, `row`, `empty_row`, `li_items`, `joined`). `reporting.py` and
  every GUI module use it; do not call `html.escape` directly.
- Verified protocol values live only in `constants.py`. Never invent a constant,
  qualifier or Option/Sub-option. New wire facts must be corroborated in
  `docs/references.md` first.
- Safety model is layered and must stay intact:
  `safety.py` (`SafetyGate`, `ConfirmationRequest`) → `services/write.py`
  (validation, confirmation, fresh read-only Identify revalidation — unicast,
  with one NameOfStation-filtered multicast fallback when the device ignores
  unicast — single send,
  read-back / post-check). No automatic retry, no rollback, no batch or
  broadcast path, unicast targets only.
- Operation text and parameters live **once** in `operations.py`
  (`set_name_spec`, `set_ip_spec`, `reset_mode_spec`, `legacy_reset_spec`,
  `confirmation_for`). The GUI (`_apply_*`, `_run_tests`), `cli.py` and
  `testrunner/runner.py` must all consume it — never copy the consequences or
  parameter dicts into a caller. The wire BlockQualifier comes from
  `codec.request_qualifier()`, which the encoders also use; do not recompute
  `mode << 1` anywhere.
- The Test Runner validates a **declared device under test**. `DEVICE_VALIDATION_SUITE`
  and `FULL_VALIDATION_SUITE` in `testrunner/cases.py` include `write.set_name`,
  `write.set_ip` and `write.reset`, because a device is not validated until those
  have been attempted; the read-only checks run first and the reset is last.
  There is **one** declaration per run (the DUT selector plus the run button),
  not a modal dialog per operation: `_run_tests` passes the same
  `WriteAuthorization` to every selected write test, uses only the declared DUT
  (or the selected device row) as the target, and logs `safety.dut_declared`
  with the parameters. Targets are one unicast device, each frame is single-shot
  with a fresh revalidation inside `WriteService` and a read-back, there is no
  retry or rollback, and a cancelled in-flight write is `outcome_unknown`.
  There is **no session-wide configuration mode**; the DUT declaration is the
  authorization for a test run, and a single/dedicated operation is authorized
  by its own confirmation dialog or `--confirm`.
  `DEVICE_READ_ONLY_SUITE` and `TOOL_SELF_TEST_SUITE` must never contain a
  `write.*` test; `dcp-cli tests` runs them only with
  `--include-writes --confirm --mac`.
- Reset modes 3 and 9 stay refused by the encoder (unverified semantics).
  Legacy FactoryReset (`05/05`) **is** implemented: BlockQualifier `0x0000`,
  full reset, no mode field, through the same gate.
- DCP Signal (`05/03`) is **implemented and deliberately unconfirmed**: it lives
  in `services/signal.py`, is exposed by the Device Details tab and
  `dcp-cli signal`, and needs no confirmation
  dialog, because it stores nothing and interrupts nothing. It is still one
  unicast frame, rate-limited, never retried, and never routed through
  `WriteService` (which rejects `kind="signal"` on purpose).
- Monitoring is **user-started polling, not a background scanner**. The loop
  lives in `services/monitor.py` over the existing `DiscoveryService` (one
  ordinary Identify per cycle) and the diff/vocabulary in the pure `monitor.py`;
  it is exposed by the Monitor tab and `dcp-cli monitor`. It constructs no
  transport, writes nothing, and is part of the composition root. Keep it
  read-only, keep the interval ≥ 1 s (the shared limiter still applies), and
  keep it out of the sense of "automatic retry": a cycle is one request.
- Outcome vocabulary is part of the contract: a timeout is `outcome_unknown`,
  never "failed" or "absent"; an acknowledgement is never proof of persistence
  or of reset completion.
- The GUI thread must never do blocking I/O; work runs in the `QThread`
  workers in `gui/workers.py`, capture runs in a Scapy `AsyncSniffer` thread.

## Conventions

- Public behaviour changes require updating, in the same change:
  `README.md`, `PLAN.md`, `docs/protocol-support-matrix.md`, and the relevant
  `tests/`.
- Test vectors are synthetic (mock responder / hand-built frames) and are
  documented in `tests/fixtures/PROVENANCE.md`. Never add captures of real
  customer hardware.
- Keep operator-facing safety text (consequences, qualifier display) consistent
  with the documented semantics; it is safety-relevant, not cosmetic. Edit it in
  `operations.py`, not in the widgets.
- HTML/text rendering lives in `gui/presentation.py` as pure functions (no Qt).
  Add formatting there and keep `main_window.py` for widget wiring.
- Test case IDs use a functional namespace (`env.*`, `parser.*`, `protocol.*`,
  `validation.*`, `write.*`) and are displayed verbatim in the GUI test table,
  the event log and the HTML report. Never introduce delivery-phase numbering in
  an ID. The handler method is derived from the ID:
  `getattr(self, f"_test_{case.test_id.replace('.', '_')}")`, so an ID and its
  `_test_*` method must be renamed together. Handlers live in
  `testrunner/handlers/<namespace>.py` (one mixin per namespace that `TestRunner`
  inherits); `tests/test_testrunner_handlers.py` enforces both the ID→handler
  resolution and the namespace placement.
- Operator-visible text (window title, header badge, report header) carries the
  version and capability, not a delivery-phase number. `PHASE` is shown only in
  the About box.

## Pitfalls

- Do not commit without operator authorization; check `git status` and make
  backups before bulk edits.
- `dist/` predates the 2026-11-18/19 refactors; run `uv build` after any source
  change before shipping. The wheel must contain `cli.py`, `session.py` and both
  entry points.
- Windows/Npcap code paths cannot be executed on this Linux host; only the
  monkeypatched unit tests cover them.
- Live read-only validation is possible without sudo on a dedicated lab NIC: a
  helper interpreter (`.venv/bin/python-raw`) carries `CAP_NET_RAW`. Drive the
  same services the GUI uses (see `HANDOFF.md` § *Live hardware run*); never
  transmit a Set or Reset from an automated run without explicit operator
  authorization.
- In the validation lab, one device **rejects RTFS modes 1 and 4** with block
  error `0x02`, while modes 2, 8 and legacy `05/05` are acknowledged. Report
  that as device behaviour, never as a tool defect. Do not record the device's
  vendor, model, IDs, MAC or IP addresses in this repository.
- Platform probing is seamed through functions
  (`raw_socket_privileges`, `capture_driver_status`, `capture_requires_elevation`)
  in `transport/interfaces.py`; monkeypatch those instead of `sys.platform`.
- `fixtures.py` is **runtime data**, not test-only: `testrunner/runner.py` uses
  `FIXTURES`/`get_fixture` for the offline parser tests that ship in the app. Do
  not move it into `tests/` without replacing that dependency first.
- `gui/controller.py` (`SessionController`) owns session state (interface,
  transport, services, safety gate, device cache, result histories) and the
  operations `discover` / `monitor` / `read_get` / `signal` / `execute_write` /
  `post_check`.
  The service workers in `gui/workers.py` are thin adapters over it.
  `gui/main_window.py` is the window shell (~380 lines: widgets, menu, status
  bar, tabs, session-state properties, the per-worker `*_running` predicates,
  `_service_log`, shutdown); its session-state names are explicit delegated
  properties over the controller (no `__getattr__` hooks) so the tab mixins keep
  working. Do not add new state to the window — extend the controller. Tab
  construction **and** its slot handlers live in `gui/tabs/<tab>.py` mixins
  (discovery incl. interface lifecycle, monitor, capture incl. capture lifecycle,
  configuration, reset, device, test runner, logs) plus
  `gui/tabs/write_flow.py` (`WriteFlowMixin`) for the Set/Reset flow,
  the confirmation hand-off and the reset post-check; put new tab
  widgets/handlers there, not in the shell.
  `tests/test_gui_orchestration.py` and `tests/test_gui_controller.py` target
  controller helpers directly; keep using them instead of adding logic to the
  window shell.
