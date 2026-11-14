"""Bounded passive capture buffer and frame routing."""

from __future__ import annotations

import threading
from collections import Counter, deque
from collections.abc import Callable, Iterable
from datetime import datetime

from ..codec import parse_frame
from ..model import CapturedFrame

FrameListener = Callable[[bytes, datetime, str], None]


class FrameRouter:
    """Fan out transport frames to the capture buffer and discovery service."""

    def __init__(self) -> None:
        self._listeners: list[FrameListener] = []
        self._lock = threading.Lock()

    def add_listener(self, listener: FrameListener) -> None:
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def remove_listener(self, listener: FrameListener) -> None:
        with self._lock:
            try:
                self._listeners.remove(listener)
            except ValueError:
                pass

    def __call__(self, raw: bytes, timestamp: datetime, direction: str) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(raw, timestamp, direction)
            except Exception:
                # A listener must not break the capture thread.
                pass


class CaptureBuffer:
    def __init__(self, maxlen: int = 4000) -> None:
        self._frames: deque[CapturedFrame] = deque(maxlen=max(1, int(maxlen)))
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()
        self._dropped = 0
        self._last: CapturedFrame | None = None

    def add(self, raw: bytes, timestamp: datetime, direction: str, interface_id: str) -> CapturedFrame | None:
        parsed = parse_frame(
            raw,
            captured_at=timestamp,
            interface_id=interface_id,
            direction=direction,
        )
        item = CapturedFrame(
            timestamp=timestamp,
            interface_id=interface_id,
            direction=direction,
            raw=raw,
            parsed=parsed,
        )
        with self._lock:
            # Some capture stacks deliver locally transmitted frames twice. If
            # the exact frame was just recorded as tx, ignore the rx echo.
            if (
                direction == "rx"
                and self._last is not None
                and self._last.direction == "tx"
                and self._last.raw == raw
                and abs((timestamp - self._last.timestamp).total_seconds()) < 0.05
            ):
                return None
            if len(self._frames) == self._frames.maxlen:
                self._dropped += 1
            self._frames.append(item)
            self._last = item
            self._counts[parsed.kind] += 1
        return item

    def snapshot(self) -> list[CapturedFrame]:
        with self._lock:
            return list(self._frames)

    def clear(self) -> None:
        with self._lock:
            self._frames.clear()
            self._counts.clear()
            self._dropped = 0
            self._last = None

    @property
    def total(self) -> int:
        with self._lock:
            return len(self._frames)

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    def stats(self) -> dict[str, int]:
        with self._lock:
            result = {"total": len(self._frames), "dropped": self._dropped}
            result.update(dict(self._counts))
            return result

    def dcp_frames(self) -> Iterable[CapturedFrame]:
        return [f for f in self.snapshot() if f.parsed is not None and f.parsed.is_dcp]
