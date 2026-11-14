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

## Linux runtime libraries

The bundle carries Qt but **not** the system graphics stack and **not** a GL
driver. Qt6Gui links `libEGL.so.1` and `libGL.so.1` directly — the offscreen
platform plugin included — so even a headless start fails without them:

```
ImportError: libEGL.so.1: cannot open shared object file: No such file or directory
```

Every desktop installation already has these. On a minimal or server system:

```bash
# Debian / Ubuntu
sudo apt-get install -y --no-install-recommends \
  libegl1 libgl1 libglib2.0-0 libfontconfig1 libfreetype6 libdbus-1-3 \
  libx11-6 libx11-xcb1 libxcb1 libxcb-cursor0 libxcb-icccm4 libxcb-image0 \
  libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 \
  libxcb-xinerama0 libxcb-xkb1 libxkbcommon0 libxkbcommon-x11-0 libxi6 \
  libxrender1 libsm6 libice6

# RHEL / Fedora
sudo dnf install -y mesa-libEGL mesa-libGL libxkbcommon libxkbcommon-x11 \
  fontconfig freetype dbus-libs glib2 libX11 libxcb xcb-util-cursor \
  xcb-util-wm xcb-util-image xcb-util-keysyms xcb-util-renderutil \
  libXi libXrender libSM libICE
```

CI installs these *after* the build on purpose: bundling the GL/EGL stack would
pin one vendor dispatch layout and break on machines with a different driver.
`libxcb-cursor0` matters in practice — Qt 6.5+ refuses to start on X11 without
it and Ubuntu 22.04 does not pull it in by default.

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
