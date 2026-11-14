"""Main PySide6 window: shared controller for tabs, workers and safety UI.

Tab construction and the tab-specific orchestration that can live next to it are
in :mod:`dcpstudio.gui.tabs` (one mixin per tab). This class keeps the state and
the cross-tab workflow: transport/service lifecycle, discovery, guarded writes,
post-checks, configuration persistence and shutdown.
"""

from __future__ import annotations

import html
import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStatusBar,
    QTableWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import APP_NAME, PHASE, __version__
from ..config import load_config, save_config
from ..constants import SUPPORTED_RESET_MODES
from ..logging_setup import EventLogger
from ..model import (
    DeviceIdentity,
    DiscoveryResult,
    GetResult,
    TestResult,
    TransactionRecord,
    WriteResult,
)
from ..operations import (
    OperationSpec,
    confirmation_for,
    legacy_reset_spec,
    reset_mode_spec,
    set_ip_spec,
    set_name_spec,
)
from ..reporting import (
    SENSITIVE_WARNING,
)
from ..safety import ConfirmationRequest, SafetyGate
from ..services.capture import CaptureBuffer, FrameRouter
from ..services.discovery import DiscoveryConfig, DiscoveryService
from ..services.get import GetService
from ..services.rate_limit import RequestRateLimiter
from ..services.signal import SignalService
from ..services.write import (
    WriteAuthorization,
    WriteConfig,
    WriteRequest,
    WriteService,
    identity_text,
)
from ..transport.base import InterfaceInfo, Readiness
from ..transport.factory import create_transport
from ..transport.interfaces import enumerate_interfaces
from ..validation import (
    validate_ip_suite,
    validate_station_name,
)
from .confirmation import ConfirmationDialog
from .presentation import (
    signal_result_html,
    write_result_html,
)
from .tabs import TabBuildersMixin
from .tabs.common import (
    LEGACY_RESET_CHOICE,
)
from .tabs.common import (
    table_item as _item,
)
from .workers import (
    CaptureBridge,
    DiscoveryWorker,
    GetWorker,
    LogBridge,
    PcapLoadWorker,
    PostCheckWorker,
    TestWorker,
    WriteWorker,
)

STYLESHEET = """
QMainWindow, QWidget { background: #f4f7fb; color: #17212b;
  font-family: "Segoe UI", "Noto Sans", "DejaVu Sans", sans-serif; font-size: 13px; }
QFrame#header { background: #0e1b2d; border-radius: 12px; }
QFrame#header QLabel { background: transparent; }
QLabel#title { color: #ffffff; font-size: 24px; font-weight: 700; letter-spacing: -0.02em; }
QLabel#subtitle { color: #a9bdd6; font-size: 13px; }
QLabel#phaseBadge { background: #153a63; color: #8fc7ff; border: 1px solid #2a5b8d;
  border-radius: 999px; padding: 4px 11px; font-weight: 700; font-size: 11px; }
QLabel#bannerInfo { background: #eaf3ff; border: 1px solid #bfd8fb; border-radius: 8px;
  padding: 10px 12px; color: #174a7a; }
QLabel#bannerWarning { background: #fff6e5; border: 1px solid #f2d49b; border-radius: 8px;
  padding: 10px 12px; color: #744800; }
QLabel#bannerDanger { background: #fff0ee; border: 1px solid #f3c0b8; border-radius: 8px;
  padding: 10px 12px; color: #8c1d12; }
QLabel#bannerOk { background: #eaf8f0; border: 1px solid #b5e3c9; border-radius: 8px;
  padding: 10px 12px; color: #155c38; }
QTabWidget::pane { border: 1px solid #d8e2ee; background: #ffffff; border-radius: 10px;
  top: -1px; }
QTabBar::tab { background: transparent; color: #475569; padding: 9px 16px;
  border-bottom: 2px solid transparent; font-weight: 600; }
QTabBar::tab:selected { color: #0b6bcb; border-bottom: 2px solid #0b6bcb; }
QTabBar::tab:hover { color: #0b6bcb; }
QGroupBox { background: #ffffff; border: 1px solid #d8e2ee; border-radius: 10px;
  margin-top: 14px; padding: 14px 12px 10px; font-weight: 700; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px;
  color: #334155; background: #ffffff; }
QPushButton { background: #ffffff; border: 1px solid #c6d3e3; border-radius: 7px;
  padding: 7px 13px; font-weight: 600; color: #1e293b; }
QPushButton:hover { border-color: #0b6bcb; color: #0b6bcb; background: #f7fbff; }
QPushButton:pressed { background: #e8f2ff; }
QPushButton:disabled { color: #94a3b8; border-color: #e2e8f0; background: #f8fafc; }
QPushButton#primary { background: #0b6bcb; border: 1px solid #0b6bcb; color: #ffffff; }
QPushButton#primary:hover { background: #0857a6; border-color: #0857a6; }
QPushButton#danger { background: #b42318; border: 1px solid #b42318; color: #ffffff; }
QPushButton#danger:hover { background: #911b12; }
QLineEdit, QSpinBox, QDoubleSpinBox { background: #ffffff; border: 1px solid #c6d3e3;
  border-radius: 6px; padding: 6px 8px; selection-background-color: #cfe5ff; }
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus { border-color: #0b6bcb; }
QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled { background: #f8fafc;
  color: #94a3b8; }
QTableWidget, QTreeWidget { background: #ffffff; alternate-background-color: #f8fafc;
  border: 1px solid #d8e2ee; border-radius: 8px; gridline-color: #e7eef6;
  selection-background-color: #d9eaff; selection-color: #0b2b4a; }
QHeaderView::section { background: #eef4fb; color: #475569; border: 0;
  border-bottom: 1px solid #d8e2ee; padding: 8px; font-weight: 700; font-size: 11px;
  text-transform: uppercase; letter-spacing: 0.04em; }
QTreeWidget::item { padding: 3px; }
QPlainTextEdit { background: #0d1726; color: #d7e6f7; border: 1px solid #1e334d;
  border-radius: 8px; padding: 8px; selection-background-color: #1d4f86; }
QTextBrowser { background: #ffffff; border: 1px solid #d8e2ee; border-radius: 8px;
  padding: 10px; }
QCheckBox { spacing: 7px; }
QStatusBar { background: #e9f0f8; color: #334155; border-top: 1px solid #d8e2ee; }
QSplitter::handle { background: #e2eaf4; height: 5px; width: 5px; }
"""


class MainWindow(TabBuildersMixin, QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.config, config_warnings = load_config()
        self.event_log = EventLogger()
        self.capture = CaptureBuffer(self.config.max_capture_frames)
        self.router = FrameRouter()
        self.capture_bridge = CaptureBridge()
        self.log_bridge = LogBridge()
        self.interfaces: list[InterfaceInfo] = []
        self.current_interface: InterfaceInfo | None = None
        self.transport = None
        self.discovery_service: DiscoveryService | None = None
        self.get_service: GetService | None = None
        self.write_service: WriteService | None = None
        self.signal_service: SignalService | None = None
        self.safety_gate = SafetyGate()
        self.request_limiter: RequestRateLimiter | None = None
        self.last_readiness: Readiness | None = None
        self.device_cache: dict[tuple[str, str], DeviceIdentity] = {}
        self.selected_device: DeviceIdentity | None = None
        self.latest_discovery: DiscoveryResult | None = None
        self.discovery_runs: list[DiscoveryResult] = []
        self.latest_get_result: GetResult | None = None
        self.get_runs: list[GetResult] = []
        self.latest_write_result: WriteResult | None = None
        self.latest_reset_result: WriteResult | None = None
        self.write_runs: list[WriteResult] = []
        self.transactions: list[TransactionRecord] = []
        self.latest_tests: list[TestResult] = []
        self.discovery_worker: DiscoveryWorker | None = None
        self.test_worker: TestWorker | None = None
        self.pcap_worker: PcapLoadWorker | None = None
        self.get_worker: GetWorker | None = None
        self.write_worker: WriteWorker | None = None
        self.post_check_worker: PostCheckWorker | None = None
        self.discovery_cancel = threading.Event()
        self.test_cancel = threading.Event()
        self.get_cancel = threading.Event()
        self.write_cancel = threading.Event()
        self.post_check_cancel = threading.Event()
        self.signal_cancel = threading.Event()
        self.signal_worker = None
        self._config_target_mac: str | None = None
        self._refresh_after_state_tests = False
        self._suppress_interface_signal = False
        self._closing = False
        self._session_notes: list[str] = []

        self.setWindowTitle(
            f"{APP_NAME} {__version__} — PROFINET DCP · guarded writes"
        )
        self.resize(1440, 940)
        self.setMinimumSize(1100, 760)
        self.setStyleSheet(STYLESHEET)

        self._build_ui()
        self._build_menu()
        self._build_statusbar()

        self.capture_bridge.frame_received.connect(self._on_frame_ui)
        self.log_bridge.record_received.connect(self._on_log_record)
        self.event_log.attach(self.log_bridge.record_received.emit)
        self.router.add_listener(self._on_transport_frame)

        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._update_capture_stats)
        self._stats_timer.start(500)

        self.event_log.info(
            "app.start",
            f"{APP_NAME} {__version__} started (guarded writes)",
            {"version": __version__},
        )
        for warning in config_warnings:
            self.event_log.warning("config.load", warning)
        self._refresh_interfaces()
        self._update_report_preview()

    # ------------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(14, 14, 14, 8)
        outer.setSpacing(10)

        header = QFrame()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(18, 14, 18, 14)
        title_box = QVBoxLayout()
        title = QLabel("DCP Studio")
        title.setObjectName("title")
        subtitle = QLabel(
            "PROFINET DCP discovery, passive diagnostics and functional testing · "
            "Layer-2 only · isolated-lab use recommended"
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        badge = QLabel(f"v{__version__} · GUARDED WRITES")
        badge.setObjectName("phaseBadge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addLayout(title_box, 1)
        header_layout.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        outer.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_discovery_tab(), "Interfaces & Discovery")
        self.tabs.addTab(self._build_device_tab(), "Device Details")
        self.tabs.addTab(self._build_config_tab(), "Configuration")
        self.tabs.addTab(self._build_reset_tab(), "Reset")
        self.tabs.addTab(self._build_test_tab(), "Test Runner")
        self.tabs.addTab(self._build_capture_tab(), "Packet Capture")
        self.tabs.addTab(self._build_logs_tab(), "Logs & Reports")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        outer.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        export_json = QAction("Export JSON report…", self)
        export_json.triggered.connect(lambda: self._export_report("json"))
        export_html = QAction("Export HTML report…", self)
        export_html.triggered.connect(lambda: self._export_report("html"))
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(export_json)
        file_menu.addAction(export_html)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)
        help_menu = self.menuBar().addMenu("&Help")
        about = QAction("About DCP Studio", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

    def _build_statusbar(self) -> None:
        status = QStatusBar()
        self.setStatusBar(status)
        self.status_interface = QLabel("Interface: none")
        self.status_capture = QLabel("Capture: stopped")
        self.status_privileges = QLabel("Privileges: unknown")
        self.status_safety = QLabel("Writes: OFF")
        for widget in (
            self.status_interface,
            self.status_capture,
            self.status_privileges,
            self.status_safety,
        ):
            widget.setContentsMargins(8, 0, 8, 0)
            status.addPermanentWidget(widget)

    @staticmethod
    def _configure_table(table: QTableWidget, *, single: bool) -> None:
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
            if single
            else QAbstractItemView.SelectionMode.ExtendedSelection
        )
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.verticalHeader().setVisible(False)
        table.setWordWrap(False)
        table.horizontalHeader().setHighlightSections(False)

    # -------------------------------------------------------------- interface
    def _refresh_interfaces(self) -> None:
        if self.transport is not None and self.transport.is_capturing:
            self._stop_capture(silent=True)
        self._suppress_interface_signal = True
        try:
            self.interfaces = enumerate_interfaces(include_mock=True)
            self.interface_table.setRowCount(0)
            for iface in self.interfaces:
                row = self.interface_table.rowCount()
                self.interface_table.insertRow(row)
                self.interface_table.setItem(
                    row, 0, _item(iface.display_name, data=iface)
                )
                self.interface_table.setItem(row, 1, _item(iface.mac or "—", mono=True))
                self.interface_table.setItem(row, 2, _item(iface.addresses_text, mono=True))
                self.interface_table.setItem(row, 3, _item(iface.link_text))
                self.interface_table.setItem(row, 4, _item(iface.kind))
                self.interface_table.setItem(
                    row, 5, _item("mock" if iface.kind == "mock" else "check on select")
                )
            target_id = self.current_interface.id if self.current_interface else None
            target_row = -1
            if target_id:
                for row, iface in enumerate(self.interfaces):
                    if iface.id == target_id:
                        target_row = row
                        break
            if target_row >= 0:
                self.interface_table.selectRow(target_row)
            else:
                self.interface_table.clearSelection()
                self.interface_table.setCurrentCell(-1, -1)
            if self.current_interface is not None and target_row < 0:
                # The previously selected interface disappeared.
                try:
                    if self.transport is not None:
                        self.transport.close()
                except Exception:
                    pass
                self.transport = None
                self.discovery_service = None
                self.get_service = None
                self.write_service = None
                self.request_limiter = None
                self.current_interface = None
                self.last_readiness = None
                self.safety_gate.disable_configuration_mode()
        finally:
            self._suppress_interface_signal = False
        if self.current_interface is not None:
            self._activate_interface(self.current_interface)
        else:
            self._update_capture_controls()
            self.permission_label.setText(
                "Select one interface explicitly. The Demo (mock) row works without "
                "hardware or privileges; physical NICs should be on the PROFINET segment."
            )
            self.permission_label.setObjectName("bannerInfo")
            self.permission_label.style().unpolish(self.permission_label)
            self.permission_label.style().polish(self.permission_label)
        self.event_log.info(
            "interfaces.refreshed",
            f"{len(self.interfaces)} interface(s) enumerated",
            {"interfaces": [i.name for i in self.interfaces]},
        )

    def _on_interface_selected(self) -> None:
        if self._suppress_interface_signal:
            return
        row = self.interface_table.currentRow()
        if 0 <= row < len(self.interfaces):
            self._activate_interface(self.interfaces[row])

    def _activate_interface(self, iface: InterfaceInfo) -> None:
        if (
            self.current_interface is not None
            and self.current_interface.id == iface.id
            and self.transport is not None
        ):
            return
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass
        self.capture.clear()
        self.device_cache.clear()
        self.selected_device = None
        self.latest_discovery = None
        self.discovery_runs.clear()
        self.latest_get_result = None
        self.get_runs.clear()
        self.latest_write_result = None
        self.latest_reset_result = None
        self.write_runs.clear()
        self.safety_gate.disable_configuration_mode()
        self.transactions.clear()
        self.latest_tests = []
        self.transaction_table.setRowCount(0)
        self.device_table.setRowCount(0)
        self.device_count_label.setText("0 device(s)")
        self.test_results_table.setRowCount(0)
        self.test_summary_label.setText("No tests run.")
        self.packet_table.setRowCount(0)
        self.packet_detail.clear()
        self.packet_detail_label.setText("Select a frame to inspect it.")
        self.config_result_label.setText(
            "No configuration operation has been sent in this session."
        )
        self.reset_result_label.setText("No reset operation has been sent in this session.")
        self.reset_post_check_label.setText("")
        self.current_interface = iface
        try:
            self.transport = create_transport(iface)
            self.transport.set_frame_callback(self.router)
            self.request_limiter = RequestRateLimiter(self.config.min_request_interval_s)
            self.discovery_service = DiscoveryService(
                self.transport,
                limiter=self.request_limiter,
                event_log=self._service_log,
            )
            self.get_service = GetService(
                self.transport,
                limiter=self.request_limiter,
                event_log=self._service_log,
            )
            self.write_service = WriteService(
                self.transport,
                discovery_service=self.discovery_service,
                get_service=self.get_service,
                safety=self.safety_gate,
                limiter=self.request_limiter,
                event_log=self._service_log,
            )
            self.signal_service = SignalService(
                self.transport,
                limiter=self.request_limiter,
                event_log=self._service_log,
            )
            self.last_readiness = self.transport.readiness()
        except Exception as exc:
            self.transport = None
            self.discovery_service = None
            self.get_service = None
            self.write_service = None
            self.signal_service = None
            self.request_limiter = None
            self.last_readiness = None
            self.event_log.error("interface.activate", f"Could not activate interface: {exc}")
            self.permission_label.setText(
                f"<b>Cannot use this interface.</b><br>{html.escape(str(exc))}"
            )
            self.permission_label.setObjectName("bannerDanger")
            self.permission_label.style().unpolish(self.permission_label)
            self.permission_label.style().polish(self.permission_label)
        self._update_permission_label()
        self._update_capture_controls()
        self._show_device(None)
        self._update_report_preview()
        self.event_log.info(
            "interface.selected",
            f"Selected {iface.name} ({iface.mac or 'no MAC'})",
            {
                "interface_id": iface.id,
                "kind": iface.kind,
                "mac": iface.mac,
                "addresses": iface.addresses_text,
                "link": iface.link_text,
            },
        )

    def _update_permission_label(self) -> None:
        if self.current_interface is None or self.transport is None:
            self.permission_label.setText("Select an interface to evaluate capture readiness.")
            self.permission_label.setObjectName("bannerInfo")
        elif self.current_interface.kind == "mock":
            self.permission_label.setText(
                "<b>Demo (mock) interface.</b> No privileges, driver, or hardware required. "
                "Three simulated devices respond to Identify. Set/Reset are simulated in "
                "memory for guarded workflow testing; no hardware is affected."
            )
            self.permission_label.setObjectName("bannerOk")
        elif self.last_readiness is not None:
            readiness = self.last_readiness
            hints = "".join(f"<br>• {html.escape(h)}" for h in readiness.hints)
            if readiness.ready:
                self.permission_label.setText(
                    f"<b>Ready.</b> {html.escape(readiness.message)}"
                )
                self.permission_label.setObjectName("bannerOk")
            else:
                self.permission_label.setText(
                    f"<b>Capture may fail.</b> {html.escape(readiness.message)}"
                    f"<br><b>Remedies:</b>{hints}"
                )
                self.permission_label.setObjectName("bannerDanger")
        self.permission_label.style().unpolish(self.permission_label)
        self.permission_label.style().polish(self.permission_label)
        self.status_privileges.setText(
            f"Privileges: {'ready' if self.last_readiness and self.last_readiness.ready else 'check'}"
        )

    def _service_log(self, event: str, message: str, detail: dict) -> None:
        self.event_log.info(event, message, detail)

    # --------------------------------------------------------------- capture
    def _start_capture(self, silent: bool = False) -> bool:
        if self.transport is None:
            if not silent:
                QMessageBox.warning(self, "No interface", "Select an interface first.")
            return False
        try:
            self.transport.start_capture()
            self.last_readiness = self.transport.readiness()
            self.event_log.info(
                "capture.started",
                f"Passive capture started on {self.current_interface.name if self.current_interface else '?'}",
                {"filter": getattr(self.transport, "used_filter", "")},
            )
            self._update_capture_controls()
            return True
        except Exception as exc:
            self.last_readiness = self.transport.readiness()
            self._update_permission_label()
            self.event_log.error("capture.start_failed", str(exc))
            if not silent:
                QMessageBox.critical(
                    self,
                    "Capture could not start",
                    str(exc)
                    + "\n\nSee docs/troubleshooting.md for Linux CAP_NET_RAW and "
                    "Windows Npcap instructions.",
                )
            return False

    def _stop_capture(self, silent: bool = False) -> None:
        if self.transport is not None and self.transport.is_capturing:
            try:
                self.transport.stop_capture()
                self.event_log.info("capture.stopped", "Passive capture stopped")
            except Exception as exc:
                self.event_log.warning("capture.stop_failed", str(exc))
        self._update_capture_controls()

    def _update_capture_controls(self) -> None:
        capturing = bool(self.transport is not None and self.transport.is_capturing)
        ready = self.transport is not None
        get_running = self._get_running()
        busy = (
            self._discovery_running()
            or self._tests_running()
            or get_running
            or self._write_running()
            or self._post_check_running()
        )
        self.start_capture_button.setEnabled(ready and not capturing and not busy)
        self.stop_capture_button.setEnabled(capturing and not busy)
        self.refresh_button.setEnabled(not capturing and not busy)
        self.interface_table.setEnabled(not busy)
        self.discover_button.setEnabled(ready and not busy)
        self.cancel_discovery_button.setEnabled(self._discovery_running())
        self.run_tests_button.setEnabled(ready and not busy)
        self.cancel_tests_button.setEnabled(self._tests_running())
        self.unicast_identify_button.setEnabled(
            self.selected_device is not None and ready and not busy
        )
        self.get_blocks_button.setEnabled(
            self.selected_device is not None
            and ready
            and self.get_service is not None
            and not busy
        )
        self.cancel_get_button.setEnabled(get_running)
        self.get_preset_combo.setEnabled(not get_running)
        self.capture_state_label.setText(
            f"Capture: {'running' if capturing else 'stopped'}"
            + (f" · {self.current_interface.name}" if self.current_interface else "")
        )
        self.status_capture.setText(f"Capture: {'running' if capturing else 'stopped'}")
        if self.current_interface:
            self.status_interface.setText(
                f"Interface: {self.current_interface.name} ({self.current_interface.mac or 'no MAC'})"
            )
        else:
            self.status_interface.setText("Interface: none")
        self._update_config_controls()

    def _update_capture_stats(self) -> None:
        stats = self.capture.stats()
        text = (
            f"Captured frames: {stats.get('total', 0)} · DCP: {stats.get('dcp', 0)} · "
            f"other PROFINET: {stats.get('profinet_other', 0)} · other: {stats.get('other', 0)}"
        )
        if stats.get("dropped"):
            text += f" · dropped from display buffer: {stats['dropped']}"
        if hasattr(self, "packet_stats_label"):
            self.packet_stats_label.setText(text)

    # ------------------------------------------------------------- discovery
    def _discovery_running(self) -> bool:
        return self.discovery_worker is not None

    def _tests_running(self) -> bool:
        return self.test_worker is not None

    def _get_running(self) -> bool:
        return self.get_worker is not None

    def _write_running(self) -> bool:
        return self.write_worker is not None

    def _post_check_running(self) -> bool:
        return self.post_check_worker is not None

    def _signal_running(self) -> bool:
        return self.signal_worker is not None

    def _start_discovery(
        self, unicast_mac: str | None = None, *, apply_filter: bool = True
    ) -> None:
        if self._closing:
            return
        if self._discovery_running():
            return
        if self._tests_running() or self._get_running() or self._write_running() or self._post_check_running():
            QMessageBox.information(
                self,
                "Another operation is running",
                "Wait for the current Get, test, configuration, or reset operation to finish "
                "(or cancel it) before starting discovery.",
            )
            return
        if self.transport is None or self.discovery_service is None:
            QMessageBox.warning(self, "No interface", "Select an interface first.")
            return
        filter_name: str | None = None
        if unicast_mac is None and apply_filter:
            candidate = self.filter_edit.text().strip()
            if candidate:
                report = validate_station_name(candidate)
                if not report.ok:
                    QMessageBox.warning(
                        self, "Invalid NameOfStation filter", report.summary()
                    )
                    return
                filter_name = candidate
        if not self.transport.is_capturing and not self._start_capture():
            return
        cfg = DiscoveryConfig(
            timeout_s=self.timeout_spin.value(),
            response_delay_factor=self.delay_spin.value(),
            vlan_id=self.vlan_spin.value() or None,
            unicast_mac=unicast_mac,
            min_request_interval_s=self.config.min_request_interval_s,
            identify_filter_name=filter_name,
        )
        self.discovery_cancel = threading.Event()
        worker = DiscoveryWorker(self.discovery_service, cfg, self.discovery_cancel, parent=self)
        worker.finished_ok.connect(self._on_discovery_finished)
        worker.failed.connect(self._on_discovery_failed)
        worker.progress.connect(self._on_discovery_progress)
        worker.finished.connect(self._on_discovery_thread_finished)
        self.discovery_worker = worker
        if unicast_mac:
            self.discovery_summary_label.setText(f"Unicast Identify to {unicast_mac}…")
        elif filter_name:
            self.discovery_summary_label.setText(
                f"Discovering NameOfStation {filter_name!r}…"
            )
        else:
            self.discovery_summary_label.setText("Discovering…")
        self.discovery_warning_label.setVisible(False)
        mode = (
            f"unicast {unicast_mac}"
            if unicast_mac
            else (
                f"NameOfStation filter {filter_name!r}"
                if filter_name
                else "multicast"
            )
        )
        self.event_log.info(
            "discovery.start",
            f"Identify request ({mode})",
            {
                "interface": self.current_interface.id if self.current_interface else None,
                "timeout_s": cfg.timeout_s,
                "response_delay_factor": cfg.response_delay_factor,
                "vlan_id": cfg.vlan_id,
                "unicast_mac": unicast_mac,
                "identify_filter_name": filter_name,
            },
        )
        self._update_capture_controls()
        self.discover_button.setEnabled(False)
        self.cancel_discovery_button.setEnabled(True)
        worker.start()

    def _cancel_discovery(self) -> None:
        self.discovery_cancel.set()
        self.discovery_summary_label.setText("Cancelling discovery…")
        self.event_log.warning("discovery.cancel", "Cancellation requested by user")

    def _on_discovery_progress(self, message: str) -> None:
        self.discovery_summary_label.setText(message)

    def _on_discovery_finished(self, result: DiscoveryResult) -> None:
        self.latest_discovery = result
        self.discovery_runs.append(result)
        if len(self.discovery_runs) > 50:
            self.discovery_runs = self.discovery_runs[-50:]
        self._ingest_result(result)
        self._populate_device_table()
        self._append_transaction_rows(result.transactions)
        self.discovery_summary_label.setText(
            f"{result.outcome_text} · {len(result.devices)} device(s) · "
            f"{result.duration_ms:.0f} ms · Xid 0x{result.xid:08x} · "
            f"duplicates {result.duplicate_responses} · late {result.late_responses} · "
            f"unmatched {result.unmatched_responses}"
        )
        warnings = list(result.warnings)
        if warnings:
            self.discovery_warning_label.setText(
                "<b>Discovery notes</b><br>"
                + "<br>".join(f"• {html.escape(w)}" for w in warnings)
            )
            self.discovery_warning_label.setVisible(True)
            for warning in warnings:
                self.event_log.warning("discovery.warning", warning, {"xid": result.xid})
        else:
            self.discovery_warning_label.setVisible(False)
        self._update_report_preview()
        self._update_capture_stats()
        self._update_capture_controls()

    def _on_discovery_failed(self, message: str) -> None:
        self.discovery_summary_label.setText("Discovery failed.")
        self.event_log.error("discovery.failed", message)
        QMessageBox.critical(self, "Discovery failed", message)
        self._update_capture_controls()

    def _on_discovery_thread_finished(self) -> None:
        if self.discovery_worker is not None:
            self.discovery_worker.deleteLater()
        self.discovery_worker = None
        self._update_capture_controls()

    # ------------------------------------------------------------------- get
    # ----------------------------------------------------------- validation
    def _set_validation_label(self, label: QLabel, report) -> None:
        label.setText(report.summary())
        label.setStyleSheet(
            "color:#155c38;font-weight:600;" if report.ok else "color:#8c1d12;font-weight:600;"
        )

    def _validate_name(self) -> None:
        self._set_validation_label(self.name_validation_label, validate_station_name(self.name_edit.text()))

    def _validate_ip(self) -> None:
        self._set_validation_label(
            self.ip_validation_label,
            validate_ip_suite(
                self.ip_edit.text().strip(),
                self.mask_edit.text().strip(),
                self.gateway_edit.text().strip(),
            ),
        )

    # ------------------------------------------------------ guarded writes
    def _current_write_config(self) -> WriteConfig:
        timeout_s = max(0.5, float(self.timeout_spin.value()))
        return WriteConfig(
            timeout_s=timeout_s,
            revalidate_timeout_s=timeout_s,
            verify_timeout_s=timeout_s,
            vlan_id=self.vlan_spin.value() or None,
            min_request_interval_s=self.config.min_request_interval_s,
            verify_after_set=True,
        )

    def _toggle_configuration_mode(self) -> None:
        if self.safety_gate.configuration_mode:
            self.safety_gate.disable_configuration_mode()
            self.event_log.warning(
                "safety.configuration_mode",
                "Configuration mode disabled by the operator",
            )
        else:
            answer = QMessageBox.warning(
                self,
                "Enable configuration mode",
                "Configuration mode enables guarded DCP Set/Reset requests.\n\n"
                "Every operation still requires a per-operation confirmation and a fresh "
                "target revalidation. Use only on equipment cleared for maintenance.\n\n"
                "Enable configuration mode?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.safety_gate.enable_configuration_mode(explicit_authorization=True)
            self.event_log.warning(
                "safety.configuration_mode",
                "Configuration mode enabled with explicit operator authorization",
            )
        self._update_config_controls()
        self._update_capture_controls()

    def _sync_config_target(self) -> None:
        if not hasattr(self, "config_target_label"):
            return
        device = self.selected_device
        if device is None or self.current_interface is None:
            self._config_target_mac = None
            self.config_target_label.setText(
                "No device selected. Discover and select exactly one target first."
            )
            self.reset_target_label.setText(
                "No device selected. Discover and select exactly one target first."
            )
            return
        target = (
            f"<b>Interface:</b> {html.escape(self.current_interface.name)} "
            f"(<code>{html.escape(self.current_interface.mac or 'no MAC')}</code>)<br>"
            f"<b>Target MAC:</b> <code>{html.escape(device.mac)}</code><br>"
            f"<b>Current identity:</b> {html.escape(identity_text(device))}<br>"
            f"<b>Current name:</b> {html.escape(device.name_of_station or '<not set>')} · "
            f"<b>IP:</b> {html.escape(device.ip_text)}"
        )
        self.config_target_label.setText(target)
        self.reset_target_label.setText(target)
        if device.mac != self._config_target_mac:
            self._config_target_mac = device.mac
            self.name_edit.setText(device.name_of_station or "")
            self.ip_edit.setText(
                device.ip_address if device.ip_address and device.ip_address != "0.0.0.0" else ""
            )
            self.mask_edit.setText(
                device.subnet_mask
                if device.subnet_mask and device.subnet_mask != "0.0.0.0"
                else ""
            )
            self.gateway_edit.setText(
                device.gateway if device.gateway and device.gateway != "0.0.0.0" else ""
            )
            self.name_validation_label.setText("")
            self.ip_validation_label.setText("")

    def _update_config_controls(self) -> None:
        if not hasattr(self, "apply_name_button"):
            return
        config_on = self.safety_gate.configuration_mode
        has_target = (
            self.selected_device is not None
            and self.current_interface is not None
            and self.transport is not None
            and self.write_service is not None
        )
        busy = (
            self._discovery_running()
            or self._tests_running()
            or self._get_running()
            or self._write_running()
            or self._post_check_running()
        )
        writable = config_on and has_target and not busy
        self.apply_name_button.setEnabled(writable)
        self.apply_ip_button.setEnabled(writable)
        self.apply_reset_button.setEnabled(writable)
        if hasattr(self, "signal_button"):
            # Signal is an identification aid, not a state change: it needs a
            # target and an idle transport, but not configuration mode.
            self.signal_button.setEnabled(has_target and not busy)
        for widget in (
            self.name_edit,
            self.validate_name_button,
            self.temp_radio,
            self.perm_radio,
            self.ip_edit,
            self.mask_edit,
            self.gateway_edit,
            self.validate_ip_button,
            self.ip_temp_radio,
            self.ip_perm_radio,
            self.reset_mode_combo,
        ):
            widget.setEnabled(not busy)
        self.config_mode_button.setText(
            "Disable configuration mode" if config_on else "Enable configuration mode"
        )
        self.config_mode_button.setEnabled(not busy)
        self.config_mode_label.setText(
            "Configuration mode: <b style='color:#8c1d12'>ON</b> — each operation still "
            "requires per-operation confirmation and fresh target revalidation."
            if config_on
            else "Configuration mode: <b>OFF</b> — no Set/Reset request can be transmitted."
        )
        if hasattr(self, "status_safety"):
            self.status_safety.setText(
                "Writes: ON (per-operation confirmation required)"
                if config_on
                else "Writes: OFF"
            )
            self.status_safety.setStyleSheet(
                "color:#8c1d12;font-weight:700;" if config_on else "color:#334155;"
            )
        self.cancel_reset_button.setEnabled(
            self._post_check_running()
            or (
                self._write_running()
                and self.write_worker is not None
                and self.write_worker.request.kind == "reset"
            )
        )
        self.cancel_config_write_button.setEnabled(
            self._write_running()
            and self.write_worker is not None
            and self.write_worker.request.kind in ("set_name", "set_ip")
        )
        self.reset_post_check_button.setEnabled(
            self.latest_reset_result is not None
            and self.transport is not None
            and not busy
        )

    def _confirmation_for(
        self,
        spec: OperationSpec,
        device: DeviceIdentity,
        *,
        operation_id: str | None = None,
    ) -> ConfirmationRequest:
        if self.current_interface is None:
            raise RuntimeError("An interface must be selected before an operation")
        return confirmation_for(
            spec,
            interface_id=self.current_interface.id,
            interface_name=self.current_interface.display_name,
            target_mac=device.mac,
            target_identity=identity_text(device),
            operation_id=operation_id,
        )

    def _confirm_operation(self, request: ConfirmationRequest) -> WriteAuthorization | None:
        dialog = ConfirmationDialog(request, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            self.event_log.warning(
                "safety.confirmation_cancelled",
                f"Operator cancelled confirmation for {request.operation_text}",
                {"target": request.target_mac, "operation": request.operation_id},
            )
            return None
        self.event_log.warning(
            "safety.confirmation_accepted",
            f"Operator confirmed {request.operation_text}",
            {"target": request.target_mac, "operation": request.operation_id},
        )
        return dialog.authorization

    def _apply_name(self) -> None:
        if self.selected_device is None or self.current_interface is None:
            return
        if not self.safety_gate.configuration_mode:
            QMessageBox.warning(self, "Configuration mode off", "Enable configuration mode first.")
            return
        name = self.name_edit.text()
        report = validate_station_name(name)
        self._set_validation_label(self.name_validation_label, report)
        if not report.ok:
            QMessageBox.warning(self, "Invalid NameOfStation", report.summary())
            return
        device = self.selected_device
        permanent = self.perm_radio.isChecked()
        spec = set_name_spec(
            name, permanent=permanent, previous_name=device.name_of_station or "<not set>"
        )
        request = self._confirmation_for(spec, device)
        authorization = self._confirm_operation(request)
        if authorization is None:
            return
        self._start_write(
            WriteRequest(
                kind="set_name",
                target_mac=device.mac,
                confirmation=request,
                authorization=authorization,
                config=self._current_write_config(),
                name=name,
                permanent=permanent,
            )
        )

    def _apply_ip(self) -> None:
        if self.selected_device is None or self.current_interface is None:
            return
        if not self.safety_gate.configuration_mode:
            QMessageBox.warning(self, "Configuration mode off", "Enable configuration mode first.")
            return
        ip = self.ip_edit.text().strip()
        mask = self.mask_edit.text().strip()
        gateway = self.gateway_edit.text().strip()
        report = validate_ip_suite(ip, mask, gateway)
        self._set_validation_label(self.ip_validation_label, report)
        if not report.ok:
            QMessageBox.warning(self, "Invalid IPv4 suite", report.summary())
            return
        device = self.selected_device
        permanent = self.ip_perm_radio.isChecked()
        spec = set_ip_spec(
            ip, mask, gateway, permanent=permanent, previous_ip=device.ip_text
        )
        request = self._confirmation_for(spec, device)
        authorization = self._confirm_operation(request)
        if authorization is None:
            return
        self._start_write(
            WriteRequest(
                kind="set_ip",
                target_mac=device.mac,
                confirmation=request,
                authorization=authorization,
                config=self._current_write_config(),
                ip_address=ip,
                subnet_mask=mask,
                gateway=gateway,
                permanent=permanent,
            )
        )

    def _apply_reset(self) -> None:
        if self.selected_device is None or self.current_interface is None:
            return
        if not self.safety_gate.configuration_mode:
            QMessageBox.warning(self, "Configuration mode off", "Enable configuration mode first.")
            return
        choice = self.reset_mode_combo.currentData()
        device = self.selected_device
        if choice == LEGACY_RESET_CHOICE:
            request = self._confirmation_for(legacy_reset_spec(), device)
            authorization = self._confirm_operation(request)
            if authorization is None:
                return
            self._start_write(
                WriteRequest(
                    kind="reset_legacy",
                    target_mac=device.mac,
                    confirmation=request,
                    authorization=authorization,
                    config=self._current_write_config(),
                )
            )
            return
        if not isinstance(choice, int) or choice not in SUPPORTED_RESET_MODES:
            QMessageBox.warning(self, "Unsupported reset", "This reset mode is not implemented.")
            return
        mode = int(choice)
        request = self._confirmation_for(reset_mode_spec(mode), device)
        authorization = self._confirm_operation(request)
        if authorization is None:
            return
        self._start_write(
            WriteRequest(
                kind="reset",
                target_mac=device.mac,
                confirmation=request,
                authorization=authorization,
                config=self._current_write_config(),
                reset_mode=mode,
            )
        )

    def _start_write(self, request: WriteRequest) -> None:
        if self.write_service is None:
            QMessageBox.warning(self, "No interface", "Select an interface first.")
            return
        if (
            self._write_running()
            or self._post_check_running()
            or self._discovery_running()
            or self._get_running()
            or self._tests_running()
        ):
            QMessageBox.information(
                self, "Another operation is running", "Wait for the current operation to finish."
            )
            return
        if self.transport is not None and not self.transport.is_capturing:
            if not self._start_capture():
                return
        self.write_cancel = threading.Event()
        worker = WriteWorker(
            self.write_service,
            request,
            self.write_cancel,
            parent=self,
        )
        worker.finished_ok.connect(self._on_write_finished)
        worker.failed.connect(self._on_write_failed)
        worker.progress.connect(self._on_write_progress)
        worker.finished.connect(self._on_write_thread_finished)
        self.write_worker = worker
        message = (
            f"<b>{html.escape(request.confirmation.operation_text)}</b> in progress… "
            "A fresh unicast Identify revalidation is performed before transmission."
        )
        if request.kind == "reset":
            self.reset_result_label.setText(message)
            self.reset_post_check_label.setText("")
        else:
            self.config_result_label.setText(message)
        self.event_log.warning(
            "write.start",
            f"{request.confirmation.operation_text} authorized for {request.target_mac}",
            {
                "kind": request.kind,
                "target": request.target_mac,
                "parameters": request.confirmation.proposed_parameters,
                "qualifier": request.confirmation.proposed_parameters.get("BlockQualifier"),
            },
        )
        self._update_config_controls()
        self._update_capture_controls()
        worker.start()

    def _cancel_write(self) -> None:
        self.write_cancel.set()
        if self.write_worker is not None and self.write_worker.request.kind == "reset":
            self.reset_result_label.setText("Cancelling the state-changing operation…")
        else:
            self.config_result_label.setText("Cancelling the state-changing operation…")
        self.event_log.warning("write.cancel", "Cancellation requested by user")

    def _cancel_reset_operation(self) -> None:
        if self._post_check_running():
            self.post_check_cancel.set()
            self.reset_post_check_label.setText("Cancelling the read-only post-check…")
            self.event_log.warning("reset.post_check_cancel", "Post-check cancellation requested")
        else:
            self._cancel_write()

    def _on_write_progress(self, message: str) -> None:
        if self.write_worker is not None and self.write_worker.request.kind == "reset":
            self.reset_result_label.setText(html.escape(message))
        else:
            self.config_result_label.setText(html.escape(message))

    def _on_write_finished(self, result: WriteResult) -> None:
        self.latest_write_result = result
        self.write_runs.append(result)
        if len(self.write_runs) > 50:
            self.write_runs = self.write_runs[-50:]
        if result.operation == "reset":
            self.latest_reset_result = result
        self._append_transaction_rows(result.transactions)
        for identity in (result.before_identity, result.after_identity):
            if identity is not None:
                key = (identity.interface_id, identity.mac)
                existing = self.device_cache.get(key)
                if existing is None:
                    self.device_cache[key] = identity
                else:
                    existing.merge(identity, count_as_duplicate=False)
        if result.after_identity is not None:
            self._config_target_mac = None
            self._populate_device_table()
            for row in range(self.device_table.rowCount()):
                item = self.device_table.item(row, 0)
                device = item.data(Qt.ItemDataRole.UserRole) if item else None
                if isinstance(device, DeviceIdentity) and device.mac.lower() == result.target_mac.lower():
                    self.device_table.selectRow(row)
                    break
            self._show_device(self.selected_device)
        html_result = self._write_result_html(result)
        if result.operation == "reset":
            self.reset_result_label.setText(html_result)
            self.reset_post_check_label.setText(
                "<b>Post-action check:</b> use the read-only unicast Identify button when "
                "the device is reachable. A response proves reachability only."
                if result.state == "acknowledged"
                else ""
            )
        elif result.operation == "signal":
            # Not reached in practice: Signal never uses WriteService. Kept only
            # so a future caller cannot silently render it as a guarded write.
            self.signal_result_label.setText(signal_result_html(result))
        else:
            self.config_result_label.setText(html_result)
        level = (
            "INFO"
            if result.state == "acknowledged" and result.verification == "verified"
            else "WARNING"
        )
        self.event_log.log(
            level,
            "write.finished",
            f"{result.operation_text}: {result.outcome_text}",
            {
                "xid": result.xid,
                "target": result.target_mac,
                "state": result.state,
                "verification": result.verification,
                "block_error": result.block_error,
            },
        )
        self._update_report_preview()
        self._update_config_controls()

    def _on_write_failed(self, message: str) -> None:
        self.config_result_label.setText(
            f"<span style='color:#8c1d12'><b>State-changing operation failed.</b> "
            f"{html.escape(message)}</span>"
        )
        self.reset_result_label.setText(
            f"<span style='color:#8c1d12'><b>Reset failed.</b> {html.escape(message)}</span>"
        )
        self.event_log.error("write.failed", message)
        QMessageBox.critical(self, "State-changing operation failed", message)
        self._update_config_controls()

    def _on_write_thread_finished(self) -> None:
        if self.write_worker is not None:
            self.write_worker.deleteLater()
        self.write_worker = None
        self._update_config_controls()
        self._update_capture_controls()

    def _write_result_html(self, result: WriteResult) -> str:
        return write_result_html(result)

    def _signal_result_html(self, result: WriteResult) -> str:
        return signal_result_html(result)

    def _start_post_check(self) -> None:
        if (
            self.latest_reset_result is None
            or self.write_service is None
            or self._write_running()
            or self._post_check_running()
            or self._discovery_running()
            or self._get_running()
            or self._tests_running()
        ):
            return
        if self.transport is not None and not self.transport.is_capturing:
            if not self._start_capture():
                return
        self.post_check_cancel = threading.Event()
        worker = PostCheckWorker(
            self.write_service,
            self.latest_reset_result,
            max(0.5, float(self.timeout_spin.value())),
            self.post_check_cancel,
            parent=self,
        )
        worker.finished_ok.connect(self._on_post_check_finished)
        worker.failed.connect(self._on_post_check_failed)
        worker.progress.connect(self._on_write_progress)
        worker.finished.connect(self._on_post_check_thread_finished)
        self.post_check_worker = worker
        self.reset_post_check_label.setText(
            "Post-check: sending one read-only unicast Identify…"
        )
        self.event_log.info(
            "reset.post_check_start",
            f"Post-check started for {self.latest_reset_result.target_mac}",
            {"xid": self.latest_reset_result.xid},
        )
        self._update_config_controls()
        self._update_capture_controls()
        worker.start()

    def _on_post_check_finished(self, result: WriteResult) -> None:
        self.latest_reset_result = result
        self.latest_write_result = result
        color = "#155c38" if result.post_check_state == "responded" else "#744800"
        self.reset_post_check_label.setText(
            f"<span style='color:{color}'><b>Post-check: "
            f"{html.escape(result.post_check_state)}</b></span> · "
            f"{html.escape(result.post_check_detail)}"
        )
        if result.after_identity is not None:
            key = (result.after_identity.interface_id, result.after_identity.mac)
            existing = self.device_cache.get(key)
            if existing is None:
                self.device_cache[key] = result.after_identity
            else:
                existing.merge(result.after_identity, count_as_duplicate=False)
            self._config_target_mac = None
            self._populate_device_table()
            for row in range(self.device_table.rowCount()):
                item = self.device_table.item(row, 0)
                device = item.data(Qt.ItemDataRole.UserRole) if item else None
                if isinstance(device, DeviceIdentity) and device.mac.lower() == result.target_mac.lower():
                    self.device_table.selectRow(row)
                    break
            self._show_device(self.selected_device)
        self._append_transaction_rows(result.transactions)
        self.event_log.info(
            "reset.post_check_finished",
            f"Post-check {result.post_check_state}: {result.post_check_detail}",
            {"xid": result.post_check_xid, "target": result.target_mac},
        )
        self._update_report_preview()
        self._update_config_controls()

    def _on_post_check_failed(self, message: str) -> None:
        self.reset_post_check_label.setText(
            f"<span style='color:#8c1d12'><b>Post-check failed.</b> {html.escape(message)}</span>"
        )
        self.event_log.error("reset.post_check_failed", message)
        self._update_config_controls()

    def _on_post_check_thread_finished(self) -> None:
        if self.post_check_worker is not None:
            self.post_check_worker.deleteLater()
        self.post_check_worker = None
        self._update_config_controls()
        self._update_capture_controls()

    # -------------------------------------------------------------- shell
    def _on_tab_changed(self, index: int) -> None:
        if index == 5:
            self._repopulate_packet_table()
        elif index == 6:
            self._update_report_preview()

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            f"About {APP_NAME}",
            f"<h3>{APP_NAME} {__version__}</h3>"
            f"<p>Phase {PHASE} — PROFINET DCP discovery, passive decoding, "
            "Get reads, guarded NameOfStation/IP configuration, verified reset variants, "
            "diagnostics and functional testing.</p>"
            "<p>Scapy 2.8.0 and PySide6. DCP framing implemented from p-net and "
            "IEC 61158-6-10 (Wireshark pn_dcp).</p>"
            "<p><b>State-changing operations require configuration mode, per-operation "
            "confirmation, and fresh target revalidation.</b></p>"
            f"<p style='color:#8c1d12'>{html.escape(SENSITIVE_WARNING)}</p>",
        )

    # ---------------------------------------------------------------- close
    def closeEvent(self, event: QCloseEvent) -> None:
        self._closing = True
        self.discovery_cancel.set()
        self.test_cancel.set()
        self.get_cancel.set()
        self.write_cancel.set()
        self.post_check_cancel.set()
        self.signal_cancel.set()
        for worker in (
            self.discovery_worker,
            self.test_worker,
            self.get_worker,
            self.write_worker,
            self.post_check_worker,
            self.signal_worker,
        ):
            if worker is not None and worker.isRunning():
                worker.wait(3500)
        if self.pcap_worker is not None and self.pcap_worker.isRunning():
            # PCAP analysis is bounded but not interruptible mid-file; give it
            # more time so the QThread is not destroyed while running.
            self.pcap_worker.wait(10000)
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass
        try:
            self.config = self._current_config()
            save_config(self.config)
        except Exception as exc:
            self.event_log.warning("config.save_failed", str(exc))
        event.accept()
