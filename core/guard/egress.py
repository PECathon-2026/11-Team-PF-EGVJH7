"""Fail-closed validation of outgoing model payloads."""

from collections.abc import Mapping
from typing import Any, Iterable

from contracts.models import GuardResult


def _extract_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, bytes):
        try:
            yield value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Uninspectable binary payload") from exc
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _extract_strings(key)
            yield from _extract_strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _extract_strings(item)
    elif value is None or isinstance(value, (bool, int, float)):
        return
    else:
        raise ValueError("Unsupported payload type")


def validate_no_leakage(
    payload: Any,
    secrets: Iterable[str],
) -> GuardResult:
    if payload is None:
        return GuardResult(ok=False, reasons=["Outgoing payload is missing."])

    if secrets is None or isinstance(secrets, (str, bytes, Mapping)):
        return GuardResult(ok=False, reasons=["Secret inventory is invalid."])

    try:
        secret_values = list(secrets)
    except (TypeError, ValueError):
        return GuardResult(ok=False, reasons=["Secret inventory is invalid."])

    if not secret_values:
        return GuardResult(
            ok=False,
            reasons=["Secret inventory is empty; leakage cannot be verified."],
        )

    if any(not isinstance(secret, str) or not secret for secret in secret_values):
        return GuardResult(
            ok=False,
            reasons=["Secret inventory contains an invalid entry."],
        )

    try:
        payload_strings = list(_extract_strings(payload))
    except (TypeError, ValueError):
        return GuardResult(
            ok=False,
            reasons=["Outgoing payload could not be fully inspected."],
        )

    for secret in secret_values:
        if any(secret in text for text in payload_strings):
            return GuardResult(
                ok=False,
                reasons=["Outgoing payload contains a protected original value."],
            )

    return GuardResult(ok=True, reasons=[])
