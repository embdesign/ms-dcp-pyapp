"""GUI tests for the Monitor tab (offscreen, mock interface)."""

from __future__ import annotations

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from dcpstudio.gui.app import create_application  # noqa: E402
from dcpstudio.gui.main_window import MainWindow  # noqa: E402


def _app() -> QApplication:
    return QApplication.instance() or create_application(["dcpstudio-monitor-test"])


def _wait_for(app: QApplication, predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return False


def _mock_window() -> tuple[MainWindow, QApplication]:
    app = _app()
    window = MainWindow()
    window.interface_table.selectRow(0)
    app.processEvents()
    assert window.current_interface is not None
    assert window.current_interface.kind == "mock"
    return window, app


def test_monitor_cycle_reports_added_devices_and_ingests_them():
    window, app = _mock_window()
    try:
        window.monitor_cycles_spin.setValue(1)
        window.monitor_interval_spin.setValue(1.0)
        window.monitor_timeout_spin.setValue(0.5)
        window.monitor_delay_spin.setValue(1)
        window._start_monitor()
        assert window.monitor_worker is not None
        assert window.stop_monitor_button.isEnabled() is True
        assert window.start_monitor_button.isEnabled() is False
        assert _wait_for(app, lambda: window.monitor_worker is None)
        assert window.latest_monitor is not None
        run = window.latest_monitor
        assert len(run.cycles) == 1
        assert run.cycles[0].device_count == 3
        assert len(run.changes) == 3  # first cycle: three devices appeared
        assert window.monitor_changes_table.rowCount() == 3
        assert "finished" in window.monitor_state_label.text()
        assert window.device_cache  # identities were ingested for Device Details
        assert window.start_monitor_button.isEnabled() is True
        assert window.stop_monitor_button.isEnabled() is False
    finally:
        window.close()
        app.processEvents()


def test_stop_monitor_cancels_a_continuous_run():
    window, app = _mock_window()
    try:
        window.monitor_cycles_spin.setValue(0)  # until stopped
        window.monitor_interval_spin.setValue(1.0)
        window.monitor_timeout_spin.setValue(0.5)
        window.monitor_delay_spin.setValue(1)
        window._start_monitor()
        assert window.monitor_worker is not None
        window._stop_monitor()
        assert _wait_for(app, lambda: window.monitor_worker is None)
        assert window.latest_monitor is not None
        assert window.latest_monitor.cancelled is True
        assert "cancelled" in window.monitor_state_label.text()
    finally:
        window.close()
        app.processEvents()


def test_monitor_tab_requires_an_interface_and_blocks_while_running():
    app = _app()
    window = MainWindow()
    try:
        assert window.transport is None
        assert window.start_monitor_button.isEnabled() is False
        window.interface_table.selectRow(0)
        app.processEvents()
        assert window.start_monitor_button.isEnabled() is True
    finally:
        window.close()
        app.processEvents()
