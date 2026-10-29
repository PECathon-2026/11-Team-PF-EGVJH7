from dataclasses import dataclass
from copy import deepcopy

from core.detect.synthetic import get_synthetic_value

from .rules import normalize_type, placeholder_for


SYNTHETIC_TYPES = {"CARD", "EMAIL", "PHONE", "PERSON"}


@dataclass
class TextRedaction:
    element_id: str
    field: str
    secret_type: str
    placeholder: str
    reason: str


def get_value(obj, key, default=None):
    """Read a field from a dictionary or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


def set_value(obj, key, value):
    """Update a field in a dictionary or an object."""
    if isinstance(obj, dict):
        obj[key] = value
    else:
        setattr(obj, key, value)


def replace_spans(text, detections, element_id, field):
    """
    Replace detected sensitive spans with synthetic values where supported.

    Invalid or missing spans cause the entire field to be redacted.
    """
    matching = []

    for detection in detections:
        detected_id = get_value(detection, "element_id")
        detected_field = get_value(detection, "field")

        if str(detected_id) != str(element_id):
            continue

        if detected_field and detected_field != field:
            continue

        matching.append(detection)

    if not matching:
        return text, []

    spans = []

    for detection in matching:
        secret_type = normalize_type(
            get_value(detection, "type", "SECRET")
        )

        placeholder = placeholder_for(secret_type)

        span = get_value(detection, "span")

        reason = (
            "Sensitive information detected by the privacy detector."
        )

        # Fail closed if the detector did not provide a valid span.
        if (
            not isinstance(span, (tuple, list))
            or len(span) != 2
            or any(type(value) is not int for value in span)
        ):
            record = TextRedaction(
                str(element_id),
                field,
                secret_type,
                placeholder,
                reason + " Missing span; entire field redacted.",
            )

            return placeholder, [record]

        start, end = span

        if start < 0 or end <= start or end > len(text):
            record = TextRedaction(
                str(element_id),
                field,
                secret_type,
                placeholder,
                reason + " Invalid span; entire field redacted.",
            )

            return placeholder, [record]

        # Keep direct sanitizer output redacted.
        # The model-payload pipeline handles synthetic substitution separately.
        replacement = placeholder

        spans.append(
            (
                start,
                end,
                secret_type,
                replacement,
                reason,
            )
        )

    # Sort spans using their original positions.
    spans.sort(key=lambda item: (item[0], item[1]))

    # Merge overlapping spans.
    merged = []

    for start, end, secret_type, replacement, reason in spans:
        if merged and start < merged[-1][1]:
            (
                old_start,
                old_end,
                types,
                replacements,
                reasons,
            ) = merged[-1]

            merged[-1] = (
                old_start,
                max(old_end, end),
                types + [secret_type],
                replacements + [replacement],
                reasons + [reason],
            )
        else:
            merged.append(
                (
                    start,
                    end,
                    [secret_type],
                    [replacement],
                    [reason],
                )
            )

    result = text
    report = []

    # Replace from right to left to preserve original offsets.
    for start, end, types, replacements, reasons in reversed(merged):
        replacement = " ".join(dict.fromkeys(replacements))

        result = result[:start] + replacement + result[end:]

        for secret_type, replacement_value, reason in zip(
            types,
            replacements,
            reasons,
        ):
            report.append(
                TextRedaction(
                    str(element_id),
                    field,
                    secret_type,
                    replacement_value,
                    reason,
                )
            )

    return result, report


def sanitize_elements(elements, detections):
    """Return sanitized copies of webpage elements and a report."""
    sanitized = deepcopy(elements)
    report = []

    for element in sanitized:
        element_id = get_value(element, "id", "")

        for field in (
            "text",
            "value",
            "label",
            "placeholder",
            "title",
        ):
            original = get_value(element, field)

            if not isinstance(original, str) or not original:
                continue

            replacement, records = replace_spans(
                original,
                detections,
                element_id,
                field,
            )

            if records:
                set_value(element, field, replacement)
                report.extend(records)

        # Always protect password and OTP inputs, even if the
        # detector did not identify a sensitive span.
        element_type = str(
            get_value(element, "type", "") or ""
        ).lower()

        if element_type in {"password", "otp", "one-time-code"}:
            original_value = get_value(element, "value", "")

            if original_value:
                secret_type = (
                    "OTP"
                    if element_type in {"otp", "one-time-code"}
                    else "PASSWORD"
                )

                placeholder = placeholder_for(secret_type)

                set_value(element, "value", placeholder)

                report.append(
                    TextRedaction(
                        str(element_id),
                        "value",
                        secret_type,
                        placeholder,
                        "Sensitive input field requires redaction.",
                    )
                )

    return sanitized, report