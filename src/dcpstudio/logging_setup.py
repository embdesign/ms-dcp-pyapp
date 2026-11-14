"""Thread-safe structured event log shared by services and the GUI."""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable
from datetime import datetime
from typing import Any

from .model import LogRecordData, utc_now

LogListener = Callable[[LogRecordData], None]


class EventLogger:
    def __init__(self, maxlen: int = 5000) -> None:
        self._records: deque[LogRecordData] = deque(maxlen=maxlen)
        self._listeners: list[LogListener] = []
        self._lock = threading.Lock()

    def attach(self, listener: LogListener) -> None:
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def detach(self, listener: LogListener) -> None:
        with self._lock:
            try:
                self._listeners.remove(listener)
            except ValueError:
                pass

    def log(
        self,
        level: str,
        event: str,
        message: str,
        detail: dict[str, Any] | None = None,
        *,
        timestamp: datetime | None = None,
    ) -> LogRecordData:
        record = LogRecordData(
            timestamp=timestamp or utc_now(),
            level=level.upper(),
            event=event,
            message=message,
            detail=detail or {},
        )
        with self._lock:
            self._records.append(record)
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(record)
            except Exception:
                pass
        return record

    def info(self, event: str, message: str, detail: dict[str, Any] | None = None) -> None:
        self.log("INFO", event, message, detail)

    def warning(self, event: str, message: str, detail: dict[str, Any] | None = None) -> None:
        self.log("WARNING", event, message, detail)

    def error(self, event: str, message: str, detail: dict[str, Any] | None = None) -> None:
        self.log("ERROR", event, message, detail)

    def snapshot(self) -> list[LogRecordData]:
        with self._lock:
            return list(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


def configure_python_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("dcpstudio")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
