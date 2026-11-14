"""Conservative client-side request pacing."""

from __future__ import annotations

import threading
import time


class RequestRateLimiter:
    """Thread-safe minimum-interval gate.

    The application sends at most one discovery request per user action and
    never retries automatically. Repeating a discovery or running the bounded
    repeat test must still wait for this gate.
    """

    def __init__(self, min_interval_s: float = 1.0) -> None:
        self.min_interval_s = max(0.0, float(min_interval_s))
        self._last: float | None = None
        self._lock = threading.Lock()

    def wait(self, cancel_event: threading.Event | None = None) -> bool:
        """Block until the next request is allowed. Returns False if cancelled."""
        with self._lock:
            now = time.monotonic()
            delay = 0.0
            if self._last is not None:
                delay = max(0.0, self.min_interval_s - (now - self._last))
        if delay <= 0:
            return True
        deadline = time.monotonic() + delay
        while time.monotonic() < deadline:
            if cancel_event is not None and cancel_event.is_set():
                return False
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        return not (cancel_event is not None and cancel_event.is_set())

    def note_sent(self) -> None:
        with self._lock:
            self._last = time.monotonic()

    def remaining_s(self) -> float:
        with self._lock:
            if self._last is None:
                return 0.0
            return max(0.0, self.min_interval_s - (time.monotonic() - self._last))
