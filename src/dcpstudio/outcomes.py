"""Typed outcome vocabulary and its one display table.

Every result object used to carry plain strings such as ``"acknowledged"``,
``"no_response"`` or ``"verified"``. A typo compiled, and the operator-facing
text for the same state lived in several properties. This module owns both: the
values are ``StrEnum`` members (so JSON, comparisons and f-strings keep the
exact same wire/report representation) and the display text is defined once.

The report schema does not change: a ``StrEnum`` serializes as its ``value``.

Pure module: no I/O, no Qt, no transport.
"""

from __future__ import annotations

from enum import StrEnum


class RequestState(StrEnum):
    """State of one Get or guarded Set/Reset transaction."""

    PENDING = "pending"
    BLOCKED = "blocked"
    TARGET_UNVERIFIED = "target_unverified"
    ACKNOWLEDGED = "acknowledged"
    REJECTED = "rejected"
    SERVICE_NOT_SUPPORTED = "service_not_supported"
    NO_RESPONSE = "no_response"
    LATE_RESPONSE = "late_response"
    RESPONSE_RECEIVED = "response_received"
    CANCELLED = "cancelled"
    ERROR = "error"


class DiscoveryOutcome(StrEnum):
    """Outcome of one Identify transaction."""

    RESPONSES_RECEIVED = "responses_received"
    NO_RESPONSES = "no_responses"
    CANCELLED = "cancelled"
    ERROR = "error"


class Verification(StrEnum):
    """Result of an independent read-back after a guarded Set."""

    NOT_ATTEMPTED = "not_attempted"
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"
    REJECTED = "rejected"
    SERVICE_NOT_SUPPORTED = "service_not_supported"


class PostCheckState(StrEnum):
    """Result of the optional reachability check after a Reset."""

    NOT_ATTEMPTED = "not_attempted"
    CANCELLED = "cancelled"
    NO_RESPONSE = "no_response"
    RESPONDED = "responded"


class TransactionOutcome(StrEnum):
    """Outcome attached to a single transaction record."""

    TRANSMITTED = "transmitted"
    MATCHING_RESPONSE_RECEIVED = "matching_response_received"
    LATE_RESPONSE = "late_response"
    UNRELATED_RESPONSE_IGNORED = "unrelated_response_ignored"
    DUPLICATE_RESPONSE_IGNORED = "duplicate_response_ignored"
    OUTCOME_UNKNOWN = "outcome_unknown"


class ResponseVerdict(StrEnum):
    """Verdict from a DCP Control/Response block."""

    ACKNOWLEDGED = "acknowledged"
    REJECTED = "rejected"
    SERVICE_NOT_SUPPORTED = "service_not_supported"
    UNMATCHED = "unmatched"


GET_STATE_TEXT: dict[str, str] = {
    RequestState.PENDING: "Pending",
    RequestState.RESPONSE_RECEIVED: "Get response received",
    RequestState.LATE_RESPONSE: "Get response received after the timeout",
    RequestState.SERVICE_NOT_SUPPORTED: "Device reports DCP Get as unsupported",
    RequestState.NO_RESPONSE: "No matching response (outcome unknown)",
    RequestState.CANCELLED: "Cancelled by user",
    RequestState.ERROR: "Error",
}

WRITE_STATE_TEXT: dict[str, str] = {
    RequestState.PENDING: "Pending",
    RequestState.BLOCKED: "Blocked by safety or validation checks",
    RequestState.TARGET_UNVERIFIED: "Target could not be revalidated; no frame sent",
    RequestState.REJECTED: "Device rejected the operation",
    RequestState.SERVICE_NOT_SUPPORTED: "Device reports DCP Set as unsupported",
    RequestState.NO_RESPONSE: "No matching response (outcome unknown)",
    RequestState.LATE_RESPONSE: "Response arrived after the timeout",
    RequestState.CANCELLED: "Cancelled by user",
    RequestState.ERROR: "Error",
}

DISCOVERY_OUTCOME_TEXT: dict[str, str] = {
    DiscoveryOutcome.ERROR: "Error",
    DiscoveryOutcome.CANCELLED: "Cancelled by user",
    DiscoveryOutcome.NO_RESPONSES: "No matching responses (outcome of discovery unknown)",
}

VERIFICATION_TEXT: dict[str, str] = {
    Verification.NOT_ATTEMPTED: "No independent read-back was performed.",
    Verification.VERIFIED: "Read-back matched the requested value.",
    Verification.MISMATCH: "Read-back did not match the requested value.",
    Verification.UNKNOWN: "Read-back was inconclusive; outcome unknown.",
    Verification.REJECTED: "Read-back reported a DCP block error.",
    Verification.SERVICE_NOT_SUPPORTED: "Read-back reported Get as unsupported.",
}


def get_outcome_text(state: str) -> str:
    return GET_STATE_TEXT.get(state, str(state))


def write_outcome_text(state: str, verification: str, transmitted: bool) -> str:
    """Operator-facing text for a guarded Set/Reset result."""
    if state == RequestState.ACKNOWLEDGED and verification == Verification.VERIFIED:
        return "Acknowledged and independently read back"
    if state == RequestState.ACKNOWLEDGED:
        return "Acknowledged by device (completion not verified)"
    if state == RequestState.CANCELLED and transmitted:
        return "Cancelled after transmission (outcome unknown)"
    return WRITE_STATE_TEXT.get(state, str(state))


def discovery_outcome_text(outcome: str, device_count: int) -> str:
    if outcome == DiscoveryOutcome.RESPONSES_RECEIVED:
        return f"{device_count} device(s) responded"
    return DISCOVERY_OUTCOME_TEXT.get(outcome, str(outcome))


def verification_display_text(verification: str, detail: str = "") -> str:
    text = VERIFICATION_TEXT.get(verification, str(verification))
    return f"{text} {detail}" if detail else text
