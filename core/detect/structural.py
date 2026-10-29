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
    
    # Helper to give structural hits a span so P3's image drawer catches them
    span = (0, len(el.value)) if el.value else None
    
    if el.type == "password":
        out.append(Detection(type="PASSWORD", source="dom", element_id=el.id, field="value", span=span, bbox=el.bbox))
    ac = (el.attrs or {}).get("autocomplete", "").strip().lower()
    if ac in _AUTOCOMPLETE_MAP:
        out.append(Detection(type=_AUTOCOMPLETE_MAP[ac], source="dom", element_id=el.id, field="value", span=span, bbox=el.bbox))
    
    hay = " ".join(filter(None, [el.name, el.label, el.id, (el.attrs or {}).get("placeholder", "")])).lower()
    for words, dtype in _KEYWORD_MAP:
        if any(w in hay for w in words):
            out.append(Detection(type=dtype, source="dom", element_id=el.id, field="value", span=span, bbox=el.bbox))
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