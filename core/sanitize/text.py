from dataclasses import dataclass
from copy import deepcopy

from .rules import normalize_type, placeholder_for


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
    Replace sensitive spans using offsets from the original text.
    If a matching detection has an invalid or missing span,
    redact the entire field rather than risk exposing a secret.
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

        if (
            not isinstance(span, (tuple, list))
            or len(span) != 2
            or any(type(x) is not int for x in span)
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

        spans.append((start, end, secret_type, placeholder, reason))

    # Sort spans by their original text positions.
    spans.sort(key=lambda item: (item[0], item[1]))

    # Merge overlapping spans to avoid corrupting the text.
    merged = []

    for start, end, secret_type, placeholder, reason in spans:
        if merged and start < merged[-1][1]:
            old_start, old_end, types, placeholders, reasons = merged[-1]

            merged[-1] = (
                old_start,
                max(old_end, end),
                types + [secret_type],
                placeholders + [placeholder],
                reasons + [reason],
            )
        else:
            merged.append(
                (
                    start,
                    end,
                    [secret_type],
                    [placeholder],
                    [reason],
                )
            )

    result = text
    report = []

    # Work backwards so earlier character offsets remain valid.
    for start, end, types, placeholders, reasons in reversed(merged):
        replacement = " ".join(dict.fromkeys(placeholders))
        result = result[:start] + replacement + result[end:]

        for secret_type, placeholder, reason in zip(
            types, placeholders, reasons
        ):
            report.append(
                TextRedaction(
                    str(element_id),
                    field,
                    secret_type,
                    placeholder,
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

        for field in ("text", "value", "label", "placeholder", "title"):
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

        # Password and OTP values must be redacted based on field type,
        # even if the detector did not produce a text span.
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