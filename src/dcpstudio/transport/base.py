"""Transport abstraction: interface description, readiness, and frame I/O."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from ..interfaces import InterfaceInfo, Readiness

FrameCallback = Callable[[bytes, datetime, str], None]
"""Callback signature: (raw_frame, utc_timestamp, direction), direction is tx/rx."""


class TransportError(RuntimeError):
    """Raised for send/capture failures with an operator-readable message."""


class CaptureNotStarted(TransportError):
    pass


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
