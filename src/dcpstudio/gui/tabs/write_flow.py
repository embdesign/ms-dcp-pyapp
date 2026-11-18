"""Guarded configuration/reset flow and the read-only reset post-check.

The tab builders for the Configuration and Reset tabs live in
:mod:`dcpstudio.gui.tabs.configuration` and ``.reset``; this mixin holds the
cross-tab behaviour they trigger: field validation, the confirmation dialog
hand-off, the single ``WriteWorker`` send, and the read-only post-check. The
safety rules themselves stay in ``operations.py`` / ``services/write.py``.
"""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QLabel, QMessageBox

from ...constants import SUPPORTED_RESET_MODES
from ...html_render import esc
from ...model import DeviceIdentity, WriteResult
from ...operations import (
    OperationSpec,
    confirmation_for,
    legacy_reset_spec,
    reset_mode_spec,
    set_ip_spec,
    set_name_spec,
)
from ...safety import ConfirmationRequest
from ...services.write import (
    WriteAuthorization,
    WriteConfig,
    WriteRequest,
    identity_text,
)
from ...validation import validate_ip_suite, validate_station_name
from ..confirmation import ConfirmationDialog
from ..presentation import signal_result_html, write_result_html
from ..workers import PostCheckWorker, WriteWorker
from .common import LEGACY_RESET_CHOICE


class WriteFlowMixin:
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
            f"<b>Interface:</b> {esc(self.current_interface.name)} "
            f"(<code>{esc(self.current_interface.mac or 'no MAC')}</code>)<br>"
            f"<b>Target MAC:</b> <code>{esc(device.mac)}</code><br>"
            f"<b>Current identity:</b> {esc(identity_text(device))}<br>"
            f"<b>Current name:</b> {esc(device.name_of_station or '<not set>')} · "
            f"<b>IP:</b> {esc(device.ip_text)}"
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

    # ------------------------------------------------------- write worker
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
            self.controller,
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
            f"<b>{esc(request.confirmation.operation_text)}</b> in progress… "
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
            self.reset_result_label.setText(esc(message))
        else:
            self.config_result_label.setText(esc(message))

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
            f"{esc(message)}</span>"
        )
        self.reset_result_label.setText(
            f"<span style='color:#8c1d12'><b>Reset failed.</b> {esc(message)}</span>"
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

    # --------------------------------------------------------- post-check
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
            self.controller,
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
            f"{esc(result.post_check_state)}</b></span> · "
            f"{esc(result.post_check_detail)}"
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
            f"<span style='color:#8c1d12'><b>Post-check failed.</b> {esc(message)}</span>"
        )
        self.event_log.error("reset.post_check_failed", message)
        self._update_config_controls()

    def _on_post_check_thread_finished(self) -> None:
        if self.post_check_worker is not None:
            self.post_check_worker.deleteLater()
        self.post_check_worker = None
        self._update_config_controls()
        self._update_capture_controls()
