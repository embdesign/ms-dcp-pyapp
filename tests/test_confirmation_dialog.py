from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialogButtonBox  # noqa: E402

from dcpstudio.gui.app import create_application  # noqa: E402
from dcpstudio.gui.confirmation import ConfirmationDialog  # noqa: E402
from dcpstudio.safety import ConfirmationRequest  # noqa: E402


def _app() -> QApplication:
    return QApplication.instance() or create_application(["dcpstudio-dialog-test"])


def _request(destructiveness: str = "state-changing"):
    return ConfirmationRequest(
        operation_id="test",
        operation_text="Set NameOfStation",
        interface_id="mock:demo0",
        target_mac="02:00:00:00:00:11",
        target_identity="02:00:00:00:00:11 | line-01 | 0x002a / 0x0101",
        proposed_parameters={"NameOfStation": "line-02"},
        destructiveness=destructiveness,
        interface_name="Demo (mock)",
    )


def _ok(dialog: ConfirmationDialog):
    return dialog.buttons.button(QDialogButtonBox.StandardButton.Ok)


def test_state_changing_dialog_requires_both_checks():
    app = _app()
    dialog = ConfirmationDialog(_request())
    try:
        assert _ok(dialog).isEnabled() is False
        dialog.authorization_check.setChecked(True)
        app.processEvents()
        assert _ok(dialog).isEnabled() is False
        dialog.maintenance_check.setChecked(True)
        app.processEvents()
        assert _ok(dialog).isEnabled() is True
        dialog.accept()
        assert dialog.authorization is not None
        assert dialog.authorization.authorization_confirmed is True
        assert dialog.authorization.safe_maintenance_confirmed is True
    finally:
        dialog.close()
        app.processEvents()


def test_factory_reset_dialog_has_no_typed_fields():
    app = _app()
    dialog = ConfirmationDialog(_request("factory-reset"))
    try:
        assert not hasattr(dialog, "typed_phrase_edit")
        assert not hasattr(dialog, "typed_mac_edit")
        dialog.authorization_check.setChecked(True)
        dialog.maintenance_check.setChecked(True)
        app.processEvents()
        assert _ok(dialog).isEnabled() is True
        dialog.accept()
        assert dialog.authorization is not None
        assert dialog.authorization.safe_maintenance_confirmed is True
    finally:
        dialog.close()
        app.processEvents()
