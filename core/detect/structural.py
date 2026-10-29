from contracts.models import Element, Detection

_AUTOCOMPLETE_MAP = {"cc-number": "CARD", "cc-csc": "CARD", "cc-exp": "CARD", "one-time-code": "OTP", "current-password": "PASSWORD", "new-password": "PASSWORD", "email": "EMAIL", "tel": "PHONE"}
_KEYWORD_MAP = [
    (("card", "cvv", "cvc", "creditcard"), "CARD"),
    (("aadhaar", "aadhar", "uid"), "AADHAAR"),
    (("pan",), "PAN"),
    (("otp", "2fa", "verification"), "OTP"),
    (("password", "passwd", "pwd"), "PASSWORD"),
    (("api", "token", "secret", "key"), "API_KEY"),
    (("address",), "ADDRESS")
]

def structural_hits(el: Element) -> list[Detection]:
    out = []
    if el.type == "password":
        out.append(Detection(type="PASSWORD", source="dom", element_id=el.id, field="value", span=None))
    ac = (el.attrs or {}).get("autocomplete", "").strip().lower()
    if ac in _AUTOCOMPLETE_MAP:
        out.append(Detection(type=_AUTOCOMPLETE_MAP[ac], source="dom", element_id=el.id, field="value", span=None))
    hay = " ".join(filter(None, [el.name, el.label, el.id, (el.attrs or {}).get("placeholder", "")])).lower()
    for words, dtype in _KEYWORD_MAP:
        if any(w in hay for w in words):
            out.append(Detection(type=dtype, source="dom", element_id=el.id, field="value", span=None))
            break
    return out
