"""Confirmation workflow for state-changing DCP operations.

Every Set/Reset request must pass this gate immediately before transmission:
explicit per-operation authorization, safe-maintenance confirmation, and a
fresh target-identity revalidation. There is no separate session-wide
"configuration mode" to arm first. This module performs no network I/O.
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
    """Per-operation confirmation plus fresh target revalidation.

    * An operation is authorized by the confirmation the operator accepts for
      that single operation; there is no session-wide arming step.
    * There is no batch or broadcast path in the model at all.
    * Confirmation is checked locally; no network I/O occurs here.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_confirmation: ConfirmationRequest | None = None

    def confirm(
        self,
        request: ConfirmationRequest,
        *,
        authorization_confirmed: bool = False,
        safe_maintenance_confirmed: bool = False,
    ) -> bool:
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
