# packaging — standalone bundles

This directory turns the repository into archives that run **without Python**
and without `uv` on the target machine.

| File | Purpose |
|---|---|
| `dcp-studio.spec` | windowed desktop bundle (`dcp-studio`, `dcp-studio.exe`) |
| `dcp-cli.spec` | console bundle (`dcp-cli`, `dcp-cli.exe`) — Qt-free |
| `launchers/*.py` | tiny entry scripts PyInstaller analyses as plain scripts |
| `../.github/actions/build-bundles/action.yml` | shared build step used by the workflows |
| `../.github/workflows/package.yml` | build on push/PR, upload artefacts |
| `../.github/workflows/release.yml` | build on a `v*` tag, attach to the GitHub Release |

Nothing here is committed as a binary: builds are produced by GitHub Actions or
locally, and `dist/` and `build/` are already ignored by `.gitignore`.

## Build locally

```bash
uv sync
uv run --with pyinstaller==6.22.3 pyinstaller --noconfirm --clean \
    --distpath dist/pyinstaller --workpath build/pyinstaller \
    packaging/dcp-studio.spec

uv run --with pyinstaller==6.22.3 pyinstaller --noconfirm --clean \
    --distpath dist/pyinstaller --workpath build/pyinstaller \
    packaging/dcp-cli.spec
```

Result:

```
dist/pyinstaller/dcp-studio/   dcp-studio[.exe] + _internal/
dist/pyinstaller/dcp-cli/      dcp-cli[.exe]   + _internal/
```

Measured Linux one-folder sizes (2026-11-14, Python 3.11, PySide6 6.12.0,
PyInstaller 6.22.3): **dcp-studio 178 MB, dcp-cli 29 MB**. Qt's own shared
libraries (including `libQt6Quick`/`libQt6Qml`/`libQt6Pdf`, pulled in as binary
dependencies) dominate the GUI bundle; the Python-level `excludes` in the spec
cannot remove them.

A wheel (`uv build`) is **not** equivalent: it still needs Python plus a
dependency install on the target.

## Cross-building is not possible

A Windows `.exe` must be produced on Windows. CI covers both platforms:

* `ubuntu-22.04` — pinned on purpose. Bundles built there need glibc 2.35, which
  covers Debian 12, Ubuntu 22.04+ and RHEL/Rocky 9. Building on `ubuntu-latest`
  (24.04, glibc 2.39) would silently exclude Debian 12.
* `windows-latest` — a Windows Server x64 runner; the output runs on Windows
  10/11.

## What the bundle does *not* remove

Raw Ethernet is a platform dependency that cannot be packaged:

* **Windows** needs **Npcap** installed separately (scapy talks to it through
  `wpcap.dll`; redistributing Npcap requires its own licence).
* **Both platforms** need elevation for any real interface — Administrator on
  Windows, root or `CAP_NET_RAW` on Linux. The existing readiness checks
  (`raw_socket_privileges`, `capture_driver_status`,
  `capture_requires_elevation`) report this instead of crashing.
* The `demo0` mock interface works unelevated, so a bundle is demonstrable on a
  locked-down machine.

Windows builds are unsigned, so SmartScreen warns on first launch. Signing needs
an Authenticode certificate kept outside this repository.

## Artefact names

```
dcp-studio-windows-x64.zip   dcp-studio-linux-x64.zip
dcp-cli-windows-x64.zip      dcp-cli-linux-x64.zip
```

Each archive contains the bundle folder (`dcp-studio/` or `dcp-cli/`); unpack it
and run the executable inside. Both launchers of the same name also accept the
CLI subcommands, but only the console bundle can print to a terminal on Windows.

## Verifying a build

```bash
./dist/pyinstaller/dcp-cli/dcp-cli --version
./dist/pyinstaller/dcp-studio/dcp-studio --version     # dispatches to the CLI

QT_QPA_PLATFORM=offscreen ./dist/pyinstaller/dcp-studio/dcp-studio &   # starts, then kill
```

The workflows run exactly these checks, plus a 15-second "the GUI did not exit
during start-up" check on Linux.
