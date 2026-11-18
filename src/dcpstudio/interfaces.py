"""Domain descriptions of a network interface and its capture readiness.

These used to live in ``transport/base.py``, which forced pure modules such as
``config`` and ``reporting`` to depend on the transport layer. They are plain
data and belong to the domain; ``transport.base`` re-exports them for the
existing imports.

The offline mock interface is described here as well, so preferences can default
to it without importing a transport implementation.

Pure module: no I/O, no Qt, no Scapy.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class InterfaceInfo:
    id: str
    name: str
    description: str
    mac: str | None
    ipv4_addresses: tuple[str, ...] = ()
    ipv6_addresses: tuple[str, ...] = ()
    is_up: bool | None = None
    is_running: bool | None = None
    is_loopback: bool = False
    is_virtual: bool = False
    kind: str = "physical"  # physical | loopback | virtual | mock
    detail: str = ""

    @property
    def display_name(self) -> str:
        if self.description and self.description != self.name:
            return f"{self.name} — {self.description}"
        return self.name

    @property
    def addresses_text(self) -> str:
        values = list(self.ipv4_addresses) + list(self.ipv6_addresses)
        return ", ".join(values) if values else "—"

    @property
    def link_text(self) -> str:
        if self.is_up is None:
            return "unknown"
        if not self.is_up:
            return "down"
        return "up" if self.is_running is not False else "up (no carrier)"


@dataclass(slots=True)
class Readiness:
    ready: bool
    privileges_ok: bool
    driver_ok: bool
    message: str
    hints: list[str] = field(default_factory=list)
    platform: str = ""
    capture_filter_ok: bool | None = None
    used_filter: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "ready": self.ready,
            "privileges_ok": self.privileges_ok,
            "driver_ok": self.driver_ok,
            "message": self.message,
            "hints": list(self.hints),
            "platform": self.platform,
            "capture_filter_ok": self.capture_filter_ok,
            "used_filter": self.used_filter,
        }


MOCK_INTERFACE_ID = "mock:demo0"
MOCK_INTERFACE = InterfaceInfo(
    id=MOCK_INTERFACE_ID,
    name="demo0",
    description="Demo (mock) — offline simulated PROFINET segment",
    mac="02:00:00:00:00:01",
    ipv4_addresses=("192.0.2.10",),
    is_up=True,
    is_running=True,
    is_virtual=True,
    kind="mock",
    detail="No hardware traffic. Used for GUI demonstration and automated tests.",
)
