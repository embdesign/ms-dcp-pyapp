"""Main PySide6 window shell: session state, menus, status bar and shutdown.

The window builds the tab set in :meth:`_build_ui` and delegates everything
tab-specific to the mixins in :mod:`dcpstudio.gui.tabs` (one module per tab, plus
``write_flow`` for the guarded Set/Reset and post-check flow). This class keeps
only what several tabs share: the delegated session-state properties over
:class:`~dcpstudio.gui.controller.SessionController`, the per-worker "is
running" predicates, the service log bridge, configuration persistence and the
shutdown sequence.
"""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
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
from ..html_render import esc
from ..logging_setup import EventLogger
from ..reporting import (
    SENSITIVE_WARNING,
)
from ..services.capture import CaptureBuffer, FrameRouter
from ..transport.base import InterfaceInfo
from .controller import SessionController
from .tabs import TabBuildersMixin
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


def _delegate(attr: str) -> property:
    """Explicit access to one :class:`SessionController` field.

    The tab mixins are mixed into this window and still read ``self.transport``
    and friends. Declaring every accessor keeps the name discoverable and
    routes writes to the controller — no ``__getattr__``/``__setattr__`` magic.
    New code should take the controller explicitly.
    """
    return property(
        lambda self: getattr(self.controller, attr),
        lambda self, value: setattr(self.controller, attr, value),
        doc=f"Session state delegated to SessionController.{attr}.",
    )


class MainWindow(TabBuildersMixin, QMainWindow):
    # Session state lives in the controller; these accessors are the only
    # window-level names the tab mixins use.
    current_interface = _delegate("current_interface")
    transport = _delegate("transport")
    discovery_service = _delegate("discovery_service")
    get_service = _delegate("get_service")
    write_service = _delegate("write_service")
    signal_service = _delegate("signal_service")
    safety_gate = _delegate("safety_gate")
    request_limiter = _delegate("request_limiter")
    last_readiness = _delegate("last_readiness")
    device_cache = _delegate("device_cache")
    selected_device = _delegate("selected_device")
    latest_discovery = _delegate("latest_discovery")
    discovery_runs = _delegate("discovery_runs")
    latest_get_result = _delegate("latest_get_result")
    get_runs = _delegate("get_runs")
    latest_write_result = _delegate("latest_write_result")
    latest_reset_result = _delegate("latest_reset_result")
    write_runs = _delegate("write_runs")
    transactions = _delegate("transactions")
    latest_tests = _delegate("latest_tests")

    def __init__(self) -> None:
        super().__init__()
        self.config, config_warnings = load_config()
        self.event_log = EventLogger()
        self.capture = CaptureBuffer(self.config.max_capture_frames)
        self.router = FrameRouter()
        self.capture_bridge = CaptureBridge()
        self.log_bridge = LogBridge()
        self.interfaces: list[InterfaceInfo] = []
        self.controller = SessionController()
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
        # Qt reads a single '&' in widget text as a mnemonic marker, so a
        # literal ampersand must be escaped as '&&' or it is swallowed and the
        # following letter is underlined ("Interfaces _Discovery").
        self.tabs.addTab(self._build_discovery_tab(), "Interfaces && Discovery")
        self.tabs.addTab(self._build_device_tab(), "Device Details")
        self.tabs.addTab(self._build_config_tab(), "Configuration")
        self.tabs.addTab(self._build_reset_tab(), "Reset")
        self.tabs.addTab(self._build_test_tab(), "Test Runner")
        self.tabs.addTab(self._build_capture_tab(), "Packet Capture")
        self.tabs.addTab(self._build_logs_tab(), "Logs && Reports")
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
    def _service_log(self, event: str, message: str, detail: dict) -> None:
        self.event_log.info(event, message, detail)

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
            f"<p style='color:#8c1d12'>{esc(SENSITIVE_WARNING)}</p>",
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
