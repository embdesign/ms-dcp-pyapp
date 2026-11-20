"""Guarded-operation catalogue tests.

These lock the operator-facing text, the qualifier shown, and the fact that the
Qt UI and the functional test runner build the *same* confirmation.
"""

from __future__ import annotations

from dcpstudio.codec import request_qualifier
from dcpstudio.operations import (
    FACTORY_RESET,
    STATE_CHANGING,
    confirmation_for,
    legacy_reset_spec,
    reset_mode_spec,
    set_ip_spec,
    set_name_spec,
)

TARGET = {
    "interface_id": "if0",
    "interface_name": "eth0",
    "target_mac": "02:00:00:00:00:11",
    "target_identity": "02:00:00:00:00:11 | line-01 | 192.0.2.11 | 0x002A/0x0101",
}


def test_set_name_spec_matches_the_wire_qualifier():
    permanent = set_name_spec("line-02", permanent=True, previous_name="line-01")
    temporary = set_name_spec("line-02", permanent=False, previous_name="<not set>")

    assert permanent.operation_id == "set_name"
    assert permanent.operation_text == "Set NameOfStation"
    assert permanent.destructiveness == STATE_CHANGING
    assert permanent.proposed_parameters["BlockQualifier"] == (
        f"0x{request_qualifier('set_name', permanent=True):04x}"
    )
    assert permanent.proposed_parameters["Persistence"] == "Permanent"
    assert permanent.proposed_parameters["Previous name"] == "line-01"
    assert temporary.proposed_parameters["Persistence"] == "Temporary"
    assert temporary.proposed_parameters["BlockQualifier"] == (
        f"0x{request_qualifier('set_name', permanent=False):04x}"
    )
    assert permanent.qualifier == permanent.proposed_parameters["BlockQualifier"]


def test_set_name_without_previous_value_omits_the_key():
    spec = set_name_spec("line-02", permanent=True)
    assert "Previous name" not in spec.proposed_parameters


def test_set_ip_spec_matches_the_wire_qualifier():
    spec = set_ip_spec(
        "192.0.2.77", "255.255.255.0", "", permanent=True, previous_ip="192.0.2.11"
    )
    assert spec.operation_id == "set_ip"
    assert spec.proposed_parameters["Gateway"] == "0.0.0.0"
    assert spec.proposed_parameters["Previous IP"] == "192.0.2.11"
    assert spec.proposed_parameters["BlockQualifier"] == (
        f"0x{request_qualifier('set_ip', permanent=True):04x}"
    )
    assert spec.destructiveness == STATE_CHANGING


def test_reset_mode_spec_marks_the_factory_reset_variants():
    for mode in (1, 2, 3, 4):
        spec = reset_mode_spec(mode)
        assert spec.operation_id == f"reset_mode_{mode}"
        assert spec.proposed_parameters["BlockQualifier"] == (
            f"0x{request_qualifier('reset', reset_mode=mode):04x}"
        )
        assert spec.destructiveness == STATE_CHANGING
    for mode in (8, 9):
        factory = reset_mode_spec(mode)
        assert factory.destructiveness == FACTORY_RESET
        assert factory.proposed_parameters["Reset mode"] == str(mode)


def test_legacy_reset_spec_has_no_mode_field():
    spec = legacy_reset_spec()
    assert spec.operation_id == "reset_legacy"
    assert spec.operation_text == "Legacy FactoryReset (05/05)"
    assert spec.proposed_parameters["Mode field"] == "none — full reset"
    assert spec.proposed_parameters["BlockQualifier"].startswith("0x0000")
    assert spec.destructiveness == FACTORY_RESET


def test_every_spec_carries_the_no_retry_wording():
    specs = [
        set_name_spec("line-02", permanent=True),
        set_ip_spec("192.0.2.77", "255.255.255.0", "", permanent=False),
        reset_mode_spec(8),
        legacy_reset_spec(),
    ]
    for spec in specs:
        text = " ".join(spec.consequences).lower()
        assert "no automatic retry" in text, spec.operation_id
        assert "acknowledgement" in text or "no automatic retry" in text


def test_confirmation_for_copies_the_spec_and_allows_an_override_id():
    spec = reset_mode_spec(8)
    confirmation = confirmation_for(spec, **TARGET)
    assert confirmation.operation_id == "reset_mode_8"
    assert confirmation.operation_text == spec.operation_text
    assert confirmation.proposed_parameters == dict(spec.proposed_parameters)
    assert confirmation.consequences == list(spec.consequences)
    assert confirmation.destructiveness == FACTORY_RESET
    assert confirmation.target_mac == TARGET["target_mac"]

    renamed = confirmation_for(spec, **TARGET, operation_id="write.reset")
    assert renamed.operation_id == "write.reset"

    # The request must own its data: mutating the spec copy is impossible
    # (frozen dataclass) and the confirmation dict is a copy.
    confirmation.proposed_parameters["Reset mode"] = "tampered"
    assert spec.proposed_parameters["Reset mode"] == "8"


def test_specs_are_frozen():
    spec = set_name_spec("line-02", permanent=True)
    try:
        spec.operation_text = "changed"  # type: ignore[misc]
    except Exception:
        pass
    else:  # pragma: no cover - frozen dataclass must reject assignment
        raise AssertionError("OperationSpec should be immutable")
