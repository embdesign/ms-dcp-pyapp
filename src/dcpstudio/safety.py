"""Safety and confirmation workflow for state-changing DCP operations.

Configuration mode is off by default. Every Set/Reset request must pass this
gate immediately before transmission: explicit configuration mode, per-operation
authorization, safe-maintenance confirmation, and a fresh target-identity
revalidation. This module performs no network I/O.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


class SafetyError(RuntimeError):
    pass


@dataclass(slots=True)
class ConfirmationRequest:
    operation_id: str
    operation_text: str
    interface_id: str
    target_mac: str
    target_identity: str
    proposed_parameters: dict[str, Any] = field(default_factory=dict)
    consequences: list[str] = field(default_factory=list)
    destructiveness: str = "state-changing"  # state-changing | factory-reset
    allows_batch: bool = False
    allows_broadcast: bool = False
    interface_name: str | None = None


class SafetyGate:
    """Explicit configuration mode plus per-operation confirmation.

    * Configuration mode is off at construction and is never enabled
      automatically by discovery or any read-only operation.
    * There is no batch or broadcast path in the model at all.
    * Confirmation is checked locally; no network I/O occurs here.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._configuration_mode = False
        self._last_confirmation: ConfirmationRequest | None = None

    @property
    def configuration_mode(self) -> bool:
        with self._lock:
            return self._configuration_mode

    def enable_configuration_mode(self, *, explicit_authorization: bool) -> None:
        if not explicit_authorization:
            raise SafetyError(
                "Configuration mode requires explicit operator authorization."
            )
        with self._lock:
            self._configuration_mode = True

    def disable_configuration_mode(self) -> None:
        with self._lock:
            self._configuration_mode = False

    def require_configuration_mode(self, operation: str) -> None:
        if not self.configuration_mode:
            raise SafetyError(
                f"{operation} is blocked: enable configuration mode explicitly first."
            )

    def confirm(
        self,
        request: ConfirmationRequest,
        *,
        authorization_confirmed: bool = False,
        safe_maintenance_confirmed: bool = False,
    ) -> bool:
        self.require_configuration_mode(request.operation_text)
        if request.allows_batch or request.allows_broadcast:
            raise SafetyError("Batch and broadcast state changes are forbidden.")
        if not authorization_confirmed:
            raise SafetyError("The operator must confirm authorization to change this equipment.")
        if not safe_maintenance_confirmed:
            raise SafetyError(
                "The operator must confirm that the equipment is in a safe maintenance state."
            )
        with self._lock:
            self._last_confirmation = request
        return True

    def revalidate_target(
        self,
        request: ConfirmationRequest,
        *,
        live_mac: str | None,
        live_identity: str | None,
    ) -> None:
        """Re-check target identity immediately before transmission."""
        if not live_mac or _normalize_mac(live_mac) != _normalize_mac(request.target_mac):
            raise SafetyError("Target identity changed or disappeared; refusing to transmit.")
        if live_identity is not None and live_identity != request.target_identity:
            raise SafetyError("Target identity text changed; refusing to transmit.")

    @property
    def last_confirmation(self) -> ConfirmationRequest | None:
        return self._last_confirmation


def _normalize_mac(value: str) -> str:
    return value.strip().replace("-", ":").lower()
