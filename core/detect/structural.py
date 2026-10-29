from contracts.models import Element, Detection


_AUTOCOMPLETE_MAP = {
    "cc-number": "CARD",
    "cc-csc": "CARD",
    "cc-exp": "CARD",
    "one-time-code": "OTP",
    "current-password": "PASSWORD",
    "new-password": "PASSWORD",
    "email": "EMAIL",
    "tel": "PHONE",
}


_KEYWORD_MAP = [
    (("card", "cvv", "cvc", "creditcard"), "CARD"),
    (("aadhaar", "aadhar", "uid"), "AADHAAR"),
    (("pan",), "PAN"),
    (("otp", "2fa", "verification"), "OTP"),
    (("password", "passwd", "pwd"), "PASSWORD"),
    (("api", "token", "secret", "key"), "API_KEY"),
]


def structural_hits(el: Element) -> list[Detection]:
    """Identify sensitive fields using DOM metadata and labels."""
    out = []

    element_type = (el.type or "").strip().lower()

    # HTML input types provide strong semantic hints.
    if element_type == "password":
        out.append(
            Detection(
                type="PASSWORD",
                source="dom",
                element_id=el.id,
                field="value",
                span=None,
            )
        )

    elif element_type == "email":
        out.append(
            Detection(
                type="EMAIL",
                source="dom",
                element_id=el.id,
                field="value",
                span=None,
            )
        )

    elif element_type == "tel":
        out.append(
            Detection(
                type="PHONE",
                source="dom",
                element_id=el.id,
                field="value",
                span=None,
            )
        )

    # Check browser autocomplete metadata.
    attrs = el.attrs or el.attributes or {}

    autocomplete = (
        attrs.get("autocomplete", "")
        .strip()
        .lower()
    )

    if autocomplete in _AUTOCOMPLETE_MAP:
        out.append(
            Detection(
                type=_AUTOCOMPLETE_MAP[autocomplete],
                source="dom",
                element_id=el.id,
                field="value",
                span=None,
            )
        )

    # Inspect labels, names, IDs, and placeholders.
    hay = " ".join(
        str(value)
        for value in (
            el.name,
            el.label,
            el.id,
            attrs.get("placeholder", ""),
        )
        if value
    ).lower()

    # Email must be handled before the generic ADDRESS rule.
    is_email_field = (
        element_type == "email"
        or "email" in hay
        or autocomplete == "email"
    )

    if is_email_field:
        out.append(
            Detection(
                type="EMAIL",
                source="dom",
                element_id=el.id,
                field="value",
                span=None,
            )
        )

    # Match the existing categories from field metadata.
    for words, detection_type in _KEYWORD_MAP:
        if any(word in hay for word in words):
            out.append(
                Detection(
                    type=detection_type,
                    source="dom",
                    element_id=el.id,
                    field="value",
                    span=None,
                )
            )
            break

    # Only classify postal-address fields as ADDRESS.
    # "Email Address" must not be treated as a postal address.
    if (
        not is_email_field
        and "address" in hay
    ):
        out.append(
            Detection(
                type="ADDRESS",
                source="dom",
                element_id=el.id,
                field="value",
                span=None,
            )
        )

    # Remove duplicate detections produced by overlapping metadata.
    unique = []
    seen = set()

    for detection in out:
        key = (
            detection.type,
            detection.source,
            detection.element_id,
            detection.field,
        )

        if key not in seen:
            seen.add(key)
            unique.append(detection)

    return unique