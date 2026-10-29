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
"""Extract sensitive source substrings for outbound-leak checks."""

import re

from core.detect import scan_text


def _value(obj, key, default=None):
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


def sensitive_canaries(snapshot, detections) -> list[str]:
    by_id = {str(_value(item, "id", "")): item for item in snapshot.elements}
    canaries = set()
    for detection in detections or []:
        element = by_id.get(str(_value(detection, "element_id", "")))
        if element is None:
            continue
        field = _value(detection, "field", "value")
        source = _value(element, field, "")
        if not isinstance(source, str) or not source:
            continue
        span = _value(detection, "span")
        if (isinstance(span, (tuple, list)) and len(span) == 2
                and all(type(index) is int for index in span)
                and 0 <= span[0] < span[1] <= len(source)):
            value = source[span[0]:span[1]]
        else:
            value = source
        if value:
            canaries.add(value)
    return sorted(canaries, key=len, reverse=True)


def task_canaries(task: str) -> list[str]:
    """Find recognizable PII and explicit credential assignments in a task."""
    values = {row.span and task[row.span[0]:row.span[1]]
              for row in scan_text(task)}
    assignment = re.compile(
        r"\b(?:password|passwd|pwd|secret|api[_ -]?key|token|authorization)"
        r"\b\s*(?:is\s+|[:=]\s*)([^\s,;]+)", re.IGNORECASE,
    )
    values.update(match.group(1) for match in assignment.finditer(task))
    values.update(match.group(1) for match in re.finditer(r"\bBearer\s+([^\s,;]+)", task, re.I))
    values.discard(None)
    return sorted((value for value in values if value), key=len, reverse=True)


class AmbiguousCredentialTask(ValueError):
    """Credential-bearing task cannot be safely separated from its secret."""


_CREDENTIAL = re.compile(
    r"\b(password|passwd|pwd|passcode|passphrase|pin|secret|"
    r"api[_ -]?key|token|authorization|credential)\b"
    r"\s*(?:(?:is)\s+|[:=]\s*|\s+)([^\s,;]+)", re.IGNORECASE,
)
_NON_VALUE = {"field", "input", "box", "form", "settings", "manager", "reset", "change", "entry", "in", "my", "the", "your"}


def sanitize_task_credentials(task: str) -> tuple[str, list[str]]:
    """Redact recognizable credential values, preserving the surrounding task.

    If a label is followed by prose that cannot be safely distinguished from a
    multiword credential, fail closed. Error strings never include task text.
    """
    if not isinstance(task, str):
        raise AmbiguousCredentialTask("Credential-bearing task cannot be sanitized.")
    matches = list(_CREDENTIAL.finditer(task))
    if not matches:
        return task, []
    values = []
    output = task
    for match in reversed(matches):
        candidate = match.group(2).rstrip(".!?)]}")
        if not candidate or candidate.casefold() in _NON_VALUE:
            continue
        end = match.start(2) + len(candidate)
        # A credential label followed by plausible prose may indicate a
        # multiword secret. Do not guess where it ends.
        remainder = task[end:].lstrip()
        if remainder and not remainder.startswith((".", "!", "?", ",", ";")):
            first = remainder.split(None, 1)[0].casefold().strip(".,!?;:")
            if first not in {"to", "then", "please"}:
                raise AmbiguousCredentialTask("Credential-bearing task cannot be sanitized.")
        values.append(candidate)
        output = output[:match.start(2)] + "[REDACTED:CREDENTIAL]" + output[end:]
    return output, sorted(set(values), key=len, reverse=True)
