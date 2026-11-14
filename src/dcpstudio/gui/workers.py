"""Qt worker threads and thread-safe signal bridges."""

from __future__ import annotations

import threading

from PySide6.QtCore import QObject, QThread, Signal

from ..model import WriteResult
from ..pcap_io import analyze_pcap
from ..services.discovery import DiscoveryConfig, DiscoveryService
from ..services.get import GetConfig, GetService
from ..services.signal import SignalService
from ..services.write import WriteRequest, WriteService
from ..testrunner.runner import TestRunner


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
        service: DiscoveryService,
        config: DiscoveryConfig,
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.config = config
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.service.discover(
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
        service: GetService,
        target_mac: str,
        config: GetConfig,
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.target_mac = target_mac
        self.config = config
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.service.get(
                self.target_mac,
                self.config,
                cancel_event=self.cancel_event,
                progress=self.progress.emit,
            )
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class SignalWorker(QThread):
    """One unguarded Control/Signal (LED flash) request."""

    finished_ok = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        service: SignalService,
        target_mac: str,
        *,
        timeout_s: float,
        vlan_id: int | None,
        cancel_event: threading.Event,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.target_mac = target_mac
        self.timeout_s = timeout_s
        self.vlan_id = vlan_id
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.service.signal(
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
        service: WriteService,
        request: WriteRequest,
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.request = request
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.service.execute(
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
        service: WriteService,
        result: WriteResult,
        timeout_s: float,
        cancel_event: threading.Event,
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.result = result
        self.timeout_s = timeout_s
        self.cancel_event = cancel_event

    def run(self) -> None:  # pragma: no cover - exercised via GUI/integration
        try:
            result = self.service.post_check(
                self.result,
                timeout_s=self.timeout_s,
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
