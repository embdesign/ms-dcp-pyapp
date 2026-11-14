"""Transport abstraction: interface description, readiness, and frame I/O."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

FrameCallback = Callable[[bytes, datetime, str], None]
"""Callback signature: (raw_frame, utc_timestamp, direction), direction is tx/rx."""


class TransportError(RuntimeError):
    """Raised for send/capture failures with an operator-readable message."""


class CaptureNotStarted(TransportError):
    pass


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


class DcpTransport(Protocol):
    interface: InterfaceInfo

    @property
    def is_capturing(self) -> bool: ...

    def set_frame_callback(self, callback: FrameCallback | None) -> None: ...

    def start_capture(self) -> None: ...

    def stop_capture(self) -> None: ...

    def send_frame(self, raw: bytes) -> None: ...

    def readiness(self) -> Readiness: ...

    def close(self) -> None: ...


class BaseTransport:
    """Shared callback bookkeeping. Subclasses implement the four I/O methods."""

    def __init__(self, interface: InterfaceInfo) -> None:
        self.interface = interface
        self._callback: FrameCallback | None = None
        self._capturing = False

    @property
    def is_capturing(self) -> bool:
        return self._capturing

    def set_frame_callback(self, callback: FrameCallback | None) -> None:
        self._callback = callback

    def _emit(self, raw: bytes, timestamp: datetime, direction: str) -> None:
        callback = self._callback
        if callback is not None:
            callback(raw, timestamp, direction)

    def start_capture(self) -> None:  # pragma: no cover - interface definition
        raise NotImplementedError

    def stop_capture(self) -> None:  # pragma: no cover - interface definition
        raise NotImplementedError

    def send_frame(self, raw: bytes) -> None:  # pragma: no cover
        raise NotImplementedError

    def readiness(self) -> Readiness:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:
        try:
            self.stop_capture()
        except Exception:
            pass
