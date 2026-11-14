"""Guarded DCP operation catalogue.

Every state-changing operation is described **once** here: the operator-facing
title, the exact parameters shown in the confirmation dialog, the consequences
and the wire BlockQualifier. The Qt UI and the functional test runner both build
their ``ConfirmationRequest`` from these specs, so the text a human approves
cannot drift between the two paths.

Pure module: no Qt, no I/O, no timing, no transport. The wire qualifier comes
from :func:`dcpstudio.codec.request_qualifier`, the same helper the encoders use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .codec import request_qualifier
from .constants import RESET_MODES
from .safety import ConfirmationRequest

STATE_CHANGING = "state-changing"
FACTORY_RESET = "factory-reset"


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """Everything the operator is shown before one guarded operation."""

    operation_id: str
    operation_text: str
    destructiveness: str
    proposed_parameters: dict[str, Any]
    consequences: tuple[str, ...]

    @property
    def qualifier(self) -> str:
        value = self.proposed_parameters.get("BlockQualifier", "")
        return str(value)


def set_name_spec(
    name: str,
    *,
    permanent: bool,
    previous_name: str | None = None,
) -> OperationSpec:
    qualifier = request_qualifier("set_name", permanent=permanent)
    parameters: dict[str, Any] = {
        "New NameOfStation": name if name else "<empty: clear name>",
        "Persistence": "Permanent" if permanent else "Temporary",
        "BlockQualifier": f"0x{qualifier:04x}",
    }
    if previous_name is not None:
        parameters["Previous name"] = previous_name or "<not set>"
    return OperationSpec(
        operation_id="set_name",
        operation_text="Set NameOfStation",
        destructiveness=STATE_CHANGING,
        proposed_parameters=parameters,
        consequences=(
            "Changing the name may abort an active PROFINET connection.",
            "A controller may need to be reconfigured or reconnected.",
            "The acknowledgement is followed by one read-only Get for verification.",
            "No automatic retry or rollback is performed.",
        ),
    )


def set_ip_spec(
    ip_address: str,
    subnet_mask: str,
    gateway: str,
    *,
    permanent: bool,
    previous_ip: str | None = None,
) -> OperationSpec:
    qualifier = request_qualifier("set_ip", permanent=permanent)
    parameters: dict[str, Any] = {
        "IP address": ip_address,
        "Subnet mask": subnet_mask,
        "Gateway": gateway or "0.0.0.0",
        "Persistence": "Permanent" if permanent else "Temporary",
        "BlockQualifier": f"0x{qualifier:04x}",
    }
    if previous_ip is not None:
        parameters["Previous IP"] = previous_ip
    return OperationSpec(
        operation_id="set_ip",
        operation_text="Set IP parameters",
        destructiveness=STATE_CHANGING,
        proposed_parameters=parameters,
        consequences=(
            "Changing IP parameters may interrupt communication immediately.",
            "Discovery does not prove that the new IP address is unused.",
            "A controller may need to be reconfigured or reconnected.",
            "The acknowledgement is followed by one read-only Get for verification.",
            "No automatic retry or rollback is performed.",
        ),
    )


def reset_mode_spec(mode: int) -> OperationSpec:
    mode = int(mode)
    qualifier = request_qualifier("reset", reset_mode=mode)
    return OperationSpec(
        operation_id=f"reset_mode_{mode}",
        operation_text="ResetToFactorySettings",
        destructiveness=FACTORY_RESET if mode == 8 else STATE_CHANGING,
        proposed_parameters={
            "Reset mode": str(mode),
            "Documented meaning": RESET_MODES.get(mode, "Unknown mode"),
            "BlockQualifier": f"0x{qualifier:04x}",
            "Option / sub-option": "05 / 06",
        },
        consequences=(
            "The device may abort active PROFINET connections and reboot.",
            "The device may stop responding temporarily; no automatic retry is performed.",
            "Device support and the exact erased data are vendor-dependent.",
            "A DCP factory reset does not necessarily erase firmware or vendor data.",
            "An acknowledgement is not proof that the reset completed.",
        ),
    )


def legacy_reset_spec() -> OperationSpec:
    qualifier = request_qualifier("reset_legacy")
    return OperationSpec(
        operation_id="reset_legacy",
        operation_text="Legacy FactoryReset (05/05)",
        destructiveness=FACTORY_RESET,
        proposed_parameters={
            "Option / sub-option": "05 / 05",
            "BlockQualifier": f"0x{qualifier:04x} (Default)",
            "Mode field": "none — full reset",
        },
        consequences=(
            "This variant has no mode field: the device performs a full reset and "
            "the erased scope cannot be selected.",
            "The device may abort active PROFINET connections and reboot.",
            "Device support and the exact erased data are vendor-dependent.",
            "A DCP factory reset does not necessarily erase firmware or vendor data.",
            "An acknowledgement is not proof that the reset completed.",
            "No automatic retry or rollback is performed.",
        ),
    )


def confirmation_for(
    spec: OperationSpec,
    *,
    interface_id: str,
    interface_name: str,
    target_mac: str,
    target_identity: str,
    operation_id: str | None = None,
) -> ConfirmationRequest:
    """Build the confirmation request the operator must accept."""
    return ConfirmationRequest(
        operation_id=operation_id or spec.operation_id,
        operation_text=spec.operation_text,
        interface_id=interface_id,
        interface_name=interface_name,
        target_mac=target_mac,
        target_identity=target_identity,
        proposed_parameters=dict(spec.proposed_parameters),
        consequences=list(spec.consequences),
        destructiveness=spec.destructiveness,
    )
