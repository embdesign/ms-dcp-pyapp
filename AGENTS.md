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
uv run pytest                               # full suite (offscreen Qt, 181 tests, ~70 s)
uv run pytest --cov=dcpstudio --cov-report=term-missing
uv run ruff check src tests tools           # configured lint gate (clean)
uv run dcp-studio                           # launch GUI
uv run dcp-cli --help                       # headless CLI (also python -m dcpstudio COMMAND)
uv run dcp-cli interfaces                   # list interfaces ('demo'/'demo0' = offline mock)
sudo -E uv run dcp-studio                   # raw L2 capture/send on Linux
uv run python tools/make_fixtures.py        # regenerate tests/fixtures/*
```

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
  are interchangeable behind it.
- Verified protocol values live only in `constants.py`. Never invent a constant,
  qualifier or Option/Sub-option. New wire facts must be corroborated in
  `docs/references.md` first.
- Safety model is layered and must stay intact:
  `safety.py` (`SafetyGate`, `ConfirmationRequest`) → `services/write.py`
  (validation, confirmation, fresh unicast-Identify revalidation, single send,
  read-back / post-check). No automatic retry, no rollback, no batch or
  broadcast path, unicast targets only.
- Guarded-operation text and parameters live **once** in `operations.py`
  (`set_name_spec`, `set_ip_spec`, `reset_mode_spec`, `legacy_reset_spec`,
  `confirmation_for`). The GUI (`_apply_*`, `_run_tests`), `cli.py` and
  `testrunner/runner.py` must all consume it — never copy the consequences or
  parameter dicts into a caller. The wire BlockQualifier comes from
  `codec.request_qualifier()`, which the encoders also use; do not recompute
  `mode << 1` anywhere.
- Reset modes 3 and 9 stay refused by the encoder (unverified semantics).
  Legacy FactoryReset (`05/05`) **is** implemented: BlockQualifier `0x0000`,
  full reset, no mode field, through the same gate.
- DCP Signal (`05/03`) is **implemented and deliberately unguarded**: it lives
  in `services/signal.py`, is exposed by the Device Details tab and
  `dcp-cli signal`, and needs no configuration mode and no authorization
  dialog, because it stores nothing and interrupts nothing. It is still one
  unicast frame, rate-limited, never retried, and never routed through
  `WriteService` (which rejects `kind="signal"` on purpose).
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
  `_test_*` method must be renamed together.
- Operator-visible text (window title, header badge, report header) carries the
  version and capability, not a delivery-phase number. `PHASE` is shown only in
  the About box.

## Pitfalls

- `.git` exists on branch `main` tracking `origin/main` with a short history
  (initial import plus documentation commits), so there is little to diff or
  revert to. Check `git status` and make backups before bulk edits; do not
  commit without operator authorization.
- `dist/` was rebuilt with `uv build` on 2026-11-14 and contains the current
  `cli.py` and both entry points. Rebuild it after any source change before
  shipping.
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
- `gui/main_window.py` is the **shared controller** (transport/service
  lifecycle, discovery, guarded writes, post-checks, shutdown). Tab construction
  and tab-local orchestration live in `gui/tabs/<tab>.py` mixins; put new tab
  widgets/handlers there. `tests/test_gui_orchestration.py` targets controller
  helpers directly; keep using it instead of adding logic to the window shell.
