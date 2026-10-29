"""Conservative task-intent filtering for minimal disclosure."""

from dataclasses import dataclass


SENSITIVE_TYPES = {
    "CARD",
    "AADHAAR",
    "PAN",
    "PASSWORD",
    "OTP",
    "API_KEY",
    "SECRET",
}


@dataclass(frozen=True)
class DisclosureDecision:
    disclose: bool
    representation: str
    reason: str


def decide_disclosure(
    data_type: str,
    task_intent: str,
    *,
    field_populated: bool = False,
    syntactically_valid: bool | None = None,
) -> DisclosureDecision:
    """Return a minimized representation, never a raw sensitive value."""

    kind = str(data_type or "OTHER").upper()
    intent = str(task_intent or "").lower()

    if kind in SENSITIVE_TYPES:
        return DisclosureDecision(
            False,
            "[PROTECTED]",
            "High-sensitivity values are never disclosed to the model.",
        )

    permitted_intents = (
        "check whether",
        "is the",
        "validate",
        "validation",
        "filled",
        "populated",
    )

    if any(term in intent for term in permitted_intents):
        if syntactically_valid is not None:
            return DisclosureDecision(
                True,
                f"valid={bool(syntactically_valid)}",
                "Only validation status is needed.",
            )

        return DisclosureDecision(
            True,
            f"populated={bool(field_populated)}",
            "Only field-presence status is needed.",
        )

    return DisclosureDecision(
        False,
        "[OMITTED]",
        "Task relevance is not established; minimize disclosure by default.",
    )