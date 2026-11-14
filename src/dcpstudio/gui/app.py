"""Application bootstrap."""

from __future__ import annotations

import sys

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from .. import APP_NAME, __version__
from .main_window import MainWindow


def create_application(argv: list[str] | None = None) -> QApplication:
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("DCP Studio")
    app.setOrganizationDomain("dcp-studio.local")
    app.setStyle("Fusion")
    font = QFont("Segoe UI")
    font.setStyleHint(QFont.StyleHint.SansSerif)
    font.setPointSize(10)
    app.setFont(font)
    return app


def run(argv: list[str] | None = None) -> int:
    app = create_application(argv)
    window = MainWindow()
    window.show()
    try:
        return app.exec()
    finally:
        # PySide6 can abort during interpreter finalization when live widgets
        # still exist; close/delete them and flush the event queue first.
        window.close()
        window.deleteLater()
        app.processEvents()
