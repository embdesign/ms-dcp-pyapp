"""Golden tests for the typed outcome vocabulary and its display text.

The strings are part of the report/JSON contract, so they are pinned here. A
rename must be a deliberate schema change, not an accident.
"""

from __future__ import annotations

import json

from dcpstudio.outcomes import (
    DiscoveryOutcome,
    PostCheckState,
    RequestState,
    ResponseVerdict,
    TransactionOutcome,
    Verification,
    discovery_outcome_text,
    get_outcome_text,
    verification_display_text,
    write_outcome_text,
)


def test_states_serialize_as_their_legacy_values():
    assert RequestState.PENDING == "pending"
    assert RequestState.BLOCKED == "blocked"
    assert RequestState.TARGET_UNVERIFIED == "target_unverified"
    assert RequestState.ACKNOWLEDGED == "acknowledged"
    assert RequestState.REJECTED == "rejected"
    assert RequestState.SERVICE_NOT_SUPPORTED == "service_not_supported"
    assert RequestState.NO_RESPONSE == "no_response"
    assert RequestState.LATE_RESPONSE == "late_response"
    assert RequestState.RESPONSE_RECEIVED == "response_received"
    assert RequestState.CANCELLED == "cancelled"
    assert RequestState.ERROR == "error"

    assert json.dumps({"state": RequestState.NO_RESPONSE}) == '{"state": "no_response"}'


def test_other_vocabularies_keep_their_values():
    assert Verification.NOT_ATTEMPTED == "not_attempted"
    assert Verification.VERIFIED == "verified"
    assert Verification.MISMATCH == "mismatch"
    assert Verification.UNKNOWN == "unknown"
    assert Verification.REJECTED == "rejected"
    assert Verification.SERVICE_NOT_SUPPORTED == "service_not_supported"

    assert PostCheckState.NOT_ATTEMPTED == "not_attempted"
    assert PostCheckState.CANCELLED == "cancelled"
    assert PostCheckState.NO_RESPONSE == "no_response"
    assert PostCheckState.RESPONDED == "responded"

    assert DiscoveryOutcome.RESPONSES_RECEIVED == "responses_received"
    assert DiscoveryOutcome.NO_RESPONSES == "no_responses"

    assert TransactionOutcome.TRANSMITTED == "transmitted"
    assert TransactionOutcome.MATCHING_RESPONSE_RECEIVED == "matching_response_received"
    assert TransactionOutcome.LATE_RESPONSE == "late_response"
    assert TransactionOutcome.UNRELATED_RESPONSE_IGNORED == "unrelated_response_ignored"
    assert TransactionOutcome.DUPLICATE_RESPONSE_IGNORED == "duplicate_response_ignored"
    assert TransactionOutcome.OUTCOME_UNKNOWN == "outcome_unknown"

    assert ResponseVerdict.ACKNOWLEDGED == "acknowledged"
    assert ResponseVerdict.REJECTED == "rejected"
    assert ResponseVerdict.SERVICE_NOT_SUPPORTED == "service_not_supported"
    assert ResponseVerdict.UNMATCHED == "unmatched"


def test_get_state_text_is_the_legacy_table():
    expected = {
        "pending": "Pending",
        "response_received": "Get response received",
        "late_response": "Get response received after the timeout",
        "service_not_supported": "Device reports DCP Get as unsupported",
        "no_response": "No matching response (outcome unknown)",
        "cancelled": "Cancelled by user",
        "error": "Error",
    }
    for state, text in expected.items():
        assert get_outcome_text(state) == text


def test_write_state_text_is_the_legacy_table():
    expected = {
        "pending": "Pending",
        "blocked": "Blocked by safety or validation checks",
        "target_unverified": "Target could not be revalidated; no frame sent",
        "rejected": "Device rejected the operation",
        "service_not_supported": "Device reports DCP Set as unsupported",
        "no_response": "No matching response (outcome unknown)",
        "late_response": "Response arrived after the timeout",
        "cancelled": "Cancelled by user",
        "error": "Error",
    }
    for state, text in expected.items():
        assert write_outcome_text(state, Verification.NOT_ATTEMPTED, False) == text


def test_write_acknowledgement_and_cancellation_variants():
    assert (
        write_outcome_text(RequestState.ACKNOWLEDGED, Verification.VERIFIED, True)
        == "Acknowledged and independently read back"
    )
    assert (
        write_outcome_text(RequestState.ACKNOWLEDGED, Verification.NOT_ATTEMPTED, True)
        == "Acknowledged by device (completion not verified)"
    )
    assert (
        write_outcome_text(RequestState.CANCELLED, Verification.NOT_ATTEMPTED, True)
        == "Cancelled after transmission (outcome unknown)"
    )
    assert (
        write_outcome_text(RequestState.CANCELLED, Verification.NOT_ATTEMPTED, False)
        == "Cancelled by user"
    )


def test_verification_text_is_the_legacy_table():
    expected = {
        "not_attempted": "No independent read-back was performed.",
        "verified": "Read-back matched the requested value.",
        "mismatch": "Read-back did not match the requested value.",
        "unknown": "Read-back was inconclusive; outcome unknown.",
        "rejected": "Read-back reported a DCP block error.",
        "service_not_supported": "Read-back reported Get as unsupported.",
    }
    for verification, text in expected.items():
        assert verification_display_text(verification) == text
    assert verification_display_text("verified", "detail") == (
        "Read-back matched the requested value. detail"
    )


def test_discovery_outcome_text_is_the_legacy_table():
    assert discovery_outcome_text("error", 0) == "Error"
    assert discovery_outcome_text("cancelled", 0) == "Cancelled by user"
    assert discovery_outcome_text("no_responses", 0) == (
        "No matching responses (outcome of discovery unknown)"
    )
    assert discovery_outcome_text("responses_received", 3) == "3 device(s) responded"


def test_unknown_values_fall_back_to_the_value():
    assert get_outcome_text("future_state") == "future_state"
    assert write_outcome_text("future_state", "whatever", False) == "future_state"
    assert verification_display_text("future_state") == "future_state"
