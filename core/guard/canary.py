"""Canary-based detection of protected markers in outgoing payloads."""

from collections.abc import Mapping
from typing import Any, Iterable

from contracts.models import GuardResult
from core.guard.egress import _extract_strings


def detect_canary_leak(
    payload: Any,
    canaries: Iterable[str],
) -> GuardResult:
    """Reject payloads containing registered canary markers."""
    if payload is None:
        return GuardResult(ok=False, reasons=["Outgoing payload is missing."])

    if canaries is None or isinstance(canaries, (str, bytes, Mapping)):
        return GuardResult(ok=False, reasons=["Canary inventory is invalid."])

    try:
        markers = list(canaries)
    except (TypeError, ValueError):
        return GuardResult(ok=False, reasons=["Canary inventory is invalid."])

    if not markers:
        return GuardResult(ok=False, reasons=["Canary inventory is empty."])

    if any(not isinstance(marker, str) or not marker for marker in markers):
        return GuardResult(
            ok=False,
            reasons=["Canary inventory contains an invalid entry."],
        )

    try:
        payload_strings = list(_extract_strings(payload))
    except (TypeError, ValueError):
        return GuardResult(
            ok=False,
            reasons=["Canary validation could not be completed."],
        )

    for marker in markers:
        if any(marker in text for text in payload_strings):
            return GuardResult(
                ok=False,
                reasons=["Outgoing payload contains a protected canary marker."],
            )

    return GuardResult(ok=True, reasons=[])