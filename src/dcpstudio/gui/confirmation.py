"""Modal confirmation dialog for guarded DCP state changes."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ..safety import ConfirmationRequest
from ..services.write import WriteAuthorization


class ConfirmationDialog(QDialog):
    """Collect authorization and safe-maintenance confirmation.

    The dialog performs no network I/O. The caller passes the resulting values to
    :class:`dcpstudio.services.write.WriteService`, which re-checks them and then
    revalidates the target immediately before transmission.
    """

    def __init__(self, request: ConfirmationRequest, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.request = request
        self._authorization: WriteAuthorization | None = None
        self.setWindowTitle("Confirm state-changing DCP operation")
        self.setModal(True)
        self.setMinimumWidth(640)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 14)
        layout.setSpacing(10)

        danger = request.destructiveness == "factory-reset"
        banner = QLabel(
            "<b>This operation changes equipment state.</b> "
            + (
                "A factory reset can interrupt communication and may erase configuration. "
                if danger
                else "It may interrupt machine communication and require a controller reconnect. "
            )
            + "Use only on equipment cleared for maintenance."
        )
        banner.setWordWrap(True)
        banner.setTextFormat(Qt.TextFormat.RichText)
        banner.setStyleSheet(
            "background:#fff0ee;border:1px solid #f3c0b8;border-radius:8px;"
            "padding:10px 12px;color:#8c1d12;"
            if danger
            else "background:#fff6e5;border:1px solid #f2d49b;border-radius:8px;"
            "padding:10px 12px;color:#744800;"
        )
        layout.addWidget(banner)

        interface_label = request.interface_name or request.interface_id
        summary = QLabel(
            f"<b>Interface:</b> {html.escape(interface_label)} "
            f"(<code>{html.escape(request.interface_id)}</code>)<br>"
            f"<b>Target MAC:</b> <code>{html.escape(request.target_mac)}</code><br>"
            f"<b>Current identity:</b> {html.escape(request.target_identity)}<br>"
            f"<b>Operation:</b> {html.escape(request.operation_text)}"
        )
        summary.setWordWrap(True)
        summary.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(summary)

        if request.proposed_parameters:
            parameters = "<br>".join(
                f"<b>{html.escape(str(key))}:</b> {html.escape(str(value))}"
                for key, value in request.proposed_parameters.items()
            )
            params = QLabel(parameters)
            params.setWordWrap(True)
            params.setTextFormat(Qt.TextFormat.RichText)
            params.setStyleSheet(
                "background:#f8fafc;border:1px solid #d8e2ee;border-radius:8px;padding:9px;"
            )
            layout.addWidget(params)

        if request.consequences:
            consequences = QLabel(
                "<b>Consequences</b><ul>"
                + "".join(f"<li>{html.escape(item)}</li>" for item in request.consequences)
                + "</ul>"
            )
            consequences.setWordWrap(True)
            consequences.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(consequences)

        checks = QVBoxLayout()
        self.authorization_check = QCheckBox(
            "I am authorized to change this equipment and understand the consequences."
        )
        self.maintenance_check = QCheckBox(
            "The equipment is in a safe maintenance state and communication loss is acceptable."
        )
        checks.addWidget(self.authorization_check)
        checks.addWidget(self.maintenance_check)
        layout.addLayout(checks)

        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        self.hint.setStyleSheet("color:#8c1d12;")
        layout.addWidget(self.hint)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Execute operation")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.authorization_check.stateChanged.connect(self._update_ok)
        self.maintenance_check.stateChanged.connect(self._update_ok)
        self._update_ok()

    @property
    def authorization(self) -> WriteAuthorization | None:
        return self._authorization

    def _update_ok(self, *_args) -> None:
        ready = self.authorization_check.isChecked() and self.maintenance_check.isChecked()
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ready)
        self.hint.setText("" if ready else "Confirm authorization and safe maintenance state.")

    def accept(self) -> None:
        self._update_ok()
        if not self.buttons.button(QDialogButtonBox.StandardButton.Ok).isEnabled():
            return
        self._authorization = WriteAuthorization(
            authorization_confirmed=self.authorization_check.isChecked(),
            safe_maintenance_confirmed=self.maintenance_check.isChecked(),
        )
        super().accept()
