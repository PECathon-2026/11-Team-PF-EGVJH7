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

    # Give structural hits a span so the image drawer can identify them.
    span = (0, len(el.value)) if el.value else None

    element_type = (el.type or "").strip().lower()
    attrs = el.attrs or {}

    if element_type == "password":
        out.append(
            Detection(
                type="PASSWORD",
                source="dom",
                element_id=el.id,
                field="value",
                span=span,
                bbox=el.bbox,
            )
        )

    ac = attrs.get("autocomplete", "").strip().lower()

    if ac in _AUTOCOMPLETE_MAP:
        out.append(
            Detection(
                type=_AUTOCOMPLETE_MAP[ac],
                source="dom",
                element_id=el.id,
                field="value",
                span=span,
                bbox=el.bbox,
            )
        )

    hay = " ".join(
        filter(
            None,
            [
                el.name,
                el.label,
                el.id,
                attrs.get("placeholder", ""),
            ],
        )
    ).lower()

    # Define this before using it in the ADDRESS check.
    is_email_field = (
        element_type == "email"
        or ac == "email"
        or "email" in hay
    )

    for words, dtype in _KEYWORD_MAP:
        if any(word in hay for word in words):
            out.append(
                Detection(
                    type=dtype,
                    source="dom",
                    element_id=el.id,
                    field="value",
                    span=span,
                    bbox=el.bbox,
                )
            )
            break

    # Detect email fields separately to avoid classifying
    # "Email Address" as a postal address.
    if is_email_field:
        out.append(
            Detection(
                type="EMAIL",
                source="dom",
                element_id=el.id,
                field="value",
                span=span,
                bbox=el.bbox,
            )
        )

    # Only classify postal-address fields as ADDRESS.
    if not is_email_field and "address" in hay:
        out.append(
            Detection(
                type="ADDRESS",
                source="dom",
                element_id=el.id,
                field="value",
                span=span,
                bbox=el.bbox,
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