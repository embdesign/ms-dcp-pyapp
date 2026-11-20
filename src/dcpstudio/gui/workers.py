"""Qt worker threads and thread-safe signal bridges."""

from __future__ import annotations

import threading

from PySide6.QtCore import QObject, QThread, Signal

from ..constants import DEFAULT_POST_CHECK_WINDOW_S
from ..model import WriteResult
from ..monitor import MonitorConfig
from ..pcap_io import analyze_pcap
from ..services.discovery import DiscoveryConfig
from ..services.get import GetConfig
from ..services.write import WriteRequest
from ..testrunner.runner import TestRunner
from .controller import SessionController


class CaptureBridge(QObject):
    frame_received = Signal(object)


class LogBridge(QObject):
    record_received = Signal(object)


class DiscoveryWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        controller: SessionController,
        config: DiscoveryConfig,
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.config = config
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.controller.discover(
                self.config,
                cancel_event=self.cancel_event,
                progress=self.progress.emit,
            )
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class GetWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        controller: SessionController,
        target_mac: str,
        config: GetConfig,
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.target_mac = target_mac
        self.config = config
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.controller.read_get(
                self.target_mac,
                self.config,
                cancel_event=self.cancel_event,
                progress=self.progress.emit,
            )
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class MonitorWorker(QThread):
    """Repeated Identify monitoring with per-cycle change reporting."""

    cycle = Signal(object)
    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        controller: SessionController,
        config: MonitorConfig,
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.config = config
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            run = self.controller.monitor(
                self.config,
                cancel_event=self.cancel_event,
                on_cycle=self.cycle.emit,
                progress=self.progress.emit,
            )
            self.finished_ok.emit(run)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class SignalWorker(QThread):
    """One unguarded Control/Signal (LED flash) request."""

    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        controller: SessionController,
        target_mac: str,
        *,
        timeout_s: float,
        vlan_id: int | None,
        cancel_event: threading.Event,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.target_mac = target_mac
        self.timeout_s = timeout_s
        self.vlan_id = vlan_id
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.controller.signal(
                self.target_mac,
                timeout_s=self.timeout_s,
                vlan_id=self.vlan_id,
                cancel_event=self.cancel_event,
                progress=self.progress.emit,
            )
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class WriteWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        controller: SessionController,
        request: WriteRequest,
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.request = request
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.controller.execute_write(
                self.request,
                cancel_event=self.cancel_event,
                progress=self.progress.emit,
            )
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class PostCheckWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        controller: SessionController,
        result: WriteResult,
        timeout_s: float,
        cancel_event: threading.Event,
        *,
        window_s: float = DEFAULT_POST_CHECK_WINDOW_S,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.result = result
        self.timeout_s = timeout_s
        self.window_s = window_s
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.controller.post_check(
                self.result,
                timeout_s=self.timeout_s,
                recheck_window_s=self.window_s,
                cancel_event=self.cancel_event,
                progress=self.progress.emit,
            )
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class TestWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int, str)
    def __init__(
        self,
        runner: TestRunner,
        selected_ids: set[str],
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.runner = runner
        self.selected_ids = selected_ids
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            results = self.runner.run(
                self.selected_ids,
                cancel_event=self.cancel_event,
                progress=self.progress.emit,
            )
            self.finished_ok.emit(results)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class PcapLoadWorker(QThread):
    finished_ok = Signal(object, str)
    failed = Signal(str)

    def __init__(self, path: str, *, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.path = path

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            frames = analyze_pcap(self.path, interface_id=f"pcap:{self.path}")
            self.finished_ok.emit(frames, self.path)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
