"""Local interface enumeration and platform readiness checks.

Scapy is used only for enumeration and raw I/O. DCP framing is implemented in
``dcpstudio.codec``.
"""

from __future__ import annotations

import ctypes
import os
import platform as _platform
import sys
from pathlib import Path

# Re-exported for compatibility: these moved to the domain module
# ``dcpstudio.interfaces`` so pure modules need not import the transport layer.
from ..interfaces import MOCK_INTERFACE as MOCK_INTERFACE
from ..interfaces import MOCK_INTERFACE_ID as MOCK_INTERFACE_ID
from ..interfaces import InterfaceInfo as InterfaceInfo

_VIRTUAL_PREFIXES = (
    "veth",
    "docker",
    "br-",
    "virbr",
    "vmnet",
    "vboxnet",
    "tun",
    "tap",
    "zt",
    "wg",
    "tailscale",
    "lo:",
)

_PLATFORM = sys.platform
_CAP_NET_RAW = 13


def _linux_cap_net_raw() -> bool | None:
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("CapEff:"):
                value = int(line.split(":", 1)[1].strip(), 16)
                return bool(value & (1 << _CAP_NET_RAW))
    except (OSError, ValueError):
        return None
    return None


def raw_socket_privileges() -> tuple[bool, str]:
    """Return ``(ok, explanation)`` for raw packet send/capture."""
    if _PLATFORM.startswith("linux"):
        if os.geteuid() == 0:
            return True, "Running as root (CAP_NET_RAW available)"
        cap = _linux_cap_net_raw()
        if cap is True:
            return True, "CAP_NET_RAW is present in the effective capability set"
        if cap is False:
            return False, "CAP_NET_RAW is not present"
        return False, "Not root and CAP_NET_RAW could not be verified"
    if _PLATFORM == "win32":
        try:
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False, "Administrator rights could not be verified"
        return admin, "Administrator" if admin else "Not running as Administrator"
    if _PLATFORM == "darwin":
        if os.geteuid() == 0:
            return True, "Running as root"
        return False, "BPF capture normally requires root or access_bpf group membership"
    return False, f"Raw-packet privileges are not verified on {_PLATFORM}"


def capture_driver_status() -> tuple[bool, str]:
    """Best-effort Npcap / libpcap availability check."""
    if _PLATFORM == "win32":
        try:
            from scapy.all import conf

            if bool(getattr(conf, "use_pcap", False)):
                return True, "Scapy reports libpcap/Npcap as active"
            npf = [
                name
                for name in getattr(conf, "ifaces", {})
                if "npf_" in str(name).lower()
                or "npf_" in str(getattr(conf.ifaces[name], "description", "")).lower()
            ]
            if npf:
                return True, "Npcap/NPF interfaces are present"
            system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
            if (system32 / "Npcap").exists() or (system32 / "wpcap.dll").exists():
                return True, "Npcap installation files were found"
            return False, "Npcap/NPF interfaces were not found"
        except Exception as exc:
            return False, f"Could not inspect Npcap state: {exc}"
    if _PLATFORM.startswith("linux"):
        try:
            from scapy.all import conf

            use_pcap = bool(getattr(conf, "use_pcap", False))
            return True, (
                "Scapy raw sockets available; libpcap capture filter "
                + ("enabled" if use_pcap else "optional")
            )
        except Exception as exc:
            return False, f"Scapy is not usable: {exc}"
    return True, "No dedicated capture driver check on this platform"


def capture_requires_elevation() -> bool:
    """Whether raw capture is refused without elevation on this platform.

    Windows/Npcap normally permits capture and injection for non-administrators
    (Wireshark does), unless Npcap was installed in "restrict to administrator"
    mode. The app therefore reports the process rights but lets the driver
    attempt the capture and surfaces its error, instead of refusing up front.
    """
    return not _PLATFORM.startswith("win")


def privilege_hints() -> list[str]:
    if _PLATFORM.startswith("linux"):
        return [
            "Run with sudo and preserve the project environment: "
            "sudo -E uv run dcp-studio",
            "Or grant capabilities to a dedicated interpreter copy, not to a shared "
            "system Python: cp \"$(readlink -f .venv/bin/python)\" .venv/bin/python-raw && "
            "sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python-raw",
            "Verify with: getcap .venv/bin/python-raw",
        ]
    if _PLATFORM == "win32":
        return [
            "Install Npcap from https://npcap.com/ (WinPcap API-compatible mode is "
            "normally required by packet tools).",
            "Start the application from an elevated terminal "
            "(Run as administrator) so the capture driver can be opened.",
            "If Npcap was installed with 'restrict to administrator' the GUI must be "
            "elevated even for passive capture.",
        ]
    if _PLATFORM == "darwin":
        return ["Run with sudo, or install ChmodBPF/access_bpf and re-login."]
    return [f"Consult your platform documentation for raw packet access on {_PLATFORM}."]


# POSIX ``struct ifreq`` flag bits (what Linux raw sockets report).
_IFF_UP = 0x0001
_IFF_LOOPBACK = 0x0008
_IFF_RUNNING = 0x0040


def _flag_int(iface: object) -> int | None:
    try:
        return int(iface.flags)
    except (TypeError, ValueError, AttributeError):
        return None


def _named_flag_set(iface: object) -> set[str] | None:
    """Return symbolic interface flags, e.g. ``{"UP", "RUNNING"}``.

    Windows/Npcap goes through libpcap, so Scapy exposes ``flags`` as a
    :class:`scapy.fields.FlagValue` built from ``pcap_if_t.flags``. Those bit
    positions are PCAP_IF_* values (LOOPBACK=0x1, UP=0x2, RUNNING=0x4,
    WIRELESS=0x8, CONNECTION_STATUS=0x10..0x60) and are **not** the POSIX
    IFF_* bits. Reading them as if they were POSIX bits reports a cabled,
    running NIC as "down" (and Wi-Fi as "loopback").

    Returns ``None`` when the platform reports a plain IFF bitmask instead
    (Linux, BSD, macOS), so the caller can fall back to POSIX bits.
    """
    flags = getattr(iface, "flags", None)
    names = getattr(flags, "names", None)
    if not isinstance(names, (list, tuple)) or not names:
        return None
    value = _flag_int(iface)
    if value is None:
        return None
    try:
        return {str(name).upper() for index, name in enumerate(names) if value & (1 << index)}
    except (TypeError, ValueError):
        return None


def _link_state_from_flags(iface: object) -> tuple[bool | None, bool | None, bool | None]:
    """Derive ``(is_up, is_running, is_loopback)`` from Scapy interface flags."""
    named = _named_flag_set(iface)
    if named is not None:
        known = named - {"NA"}
        if not known:
            return None, None, None
        is_loopback = "LOOPBACK" in known
        is_up = "UP" in known
        if is_loopback:
            is_running = "RUNNING" in known
        elif "DISCONNECTED" in known:
            # libpcap reports PCAP_IF_CONNECTION_STATUS_DISCONNECTED: the
            # adapter is enabled but has no carrier.
            is_running = False
        elif "OK" in known or "RUNNING" in known:
            is_running = True
        else:
            is_running = None
        return is_up, is_running, is_loopback

    raw = _flag_int(iface)
    if raw is None:
        return None, None, None
    return (
        bool(raw & _IFF_UP),
        bool(raw & _IFF_RUNNING),
        bool(raw & _IFF_LOOPBACK),
    )


def _sysfs_link_state(name: str) -> tuple[bool | None, bool | None]:
    """Return (up, carrier) from Linux sysfs. Values are None if unavailable."""
    base = Path("/sys/class/net") / name
    up: bool | None = None
    carrier: bool | None = None
    try:
        state = (base / "operstate").read_text(encoding="ascii").strip().lower()
        up = state in ("up", "unknown") if state else None
    except OSError:
        up = None
    try:
        carrier_text = (base / "carrier").read_text(encoding="ascii").strip()
        carrier = carrier_text == "1"
    except OSError:
        carrier = None
    return up, carrier


def _looks_virtual(name: str, description: str) -> bool:
    haystack = f"{name} {description}".lower()
    return any(haystack.startswith(prefix) or f" {prefix}" in haystack for prefix in _VIRTUAL_PREFIXES) or any(
        token in haystack
        for token in ("virtual", "vmware", "virtualbox", "hyper-v", "docker", "veth", "loopback adapter")
    )


def enumerate_interfaces(*, include_mock: bool = True) -> list[InterfaceInfo]:
    """Enumerate Scapy's local interfaces without opening capture handles.

    The mock interface is always available first, so the GUI can be exercised
    without hardware or elevated privileges.
    """
    result: list[InterfaceInfo] = [MOCK_INTERFACE] if include_mock else []
    try:
        from scapy.all import conf  # imported lazily for startup resilience
    except Exception:
        return result

    interfaces = getattr(conf, "ifaces", {}) or {}
    for key, iface in interfaces.items():
        try:
            name = str(getattr(iface, "name", key))
            description = str(getattr(iface, "description", name) or name)
            mac = getattr(iface, "mac", None)
            mac = str(mac).lower() if mac else None
            is_up, is_running, is_loopback = _link_state_from_flags(iface)
            if is_loopback is None:
                is_loopback = name == "lo"

            ips = getattr(iface, "ips", {}) or {}
            ipv4 = tuple(str(x) for x in ips.get(4, []) or ())
            ipv6 = tuple(str(x) for x in ips.get(6, []) or ())
            if not ipv4:
                single = getattr(iface, "ip", "") or ""
                ipv4 = (str(single),) if single else ()

            if _PLATFORM.startswith("linux"):
                sys_up, carrier = _sysfs_link_state(name)
                if sys_up is not None:
                    is_up = sys_up
                if carrier is not None:
                    is_running = carrier

            is_virtual = _looks_virtual(name, description)
            kind = "loopback" if is_loopback else ("virtual" if is_virtual else "physical")
            result.append(
                InterfaceInfo(
                    id=str(key),
                    name=name,
                    description=description,
                    mac=mac,
                    ipv4_addresses=ipv4,
                    ipv6_addresses=ipv6,
                    is_up=is_up,
                    is_running=is_running,
                    is_loopback=is_loopback,
                    is_virtual=is_virtual,
                    kind=kind,
                )
            )
        except Exception:
            continue

    def sort_key(item: InterfaceInfo) -> tuple[int, int, str]:
        if item.kind == "mock":
            return (0, 0, item.name)
        # Physical NICs first, then virtual/loopback; up links before down ones.
        group = 1 if item.kind == "physical" else 2
        return (group, 0 if item.is_up else 1, item.name)

    result.sort(key=sort_key)
    return result


def find_interface(interface_id: str, *, include_mock: bool = True) -> InterfaceInfo | None:
    for item in enumerate_interfaces(include_mock=include_mock):
        if item.id == interface_id:
            return item
    return None


def platform_label() -> str:
    return f"{_platform.system()} {_platform.release()} ({_PLATFORM})"
