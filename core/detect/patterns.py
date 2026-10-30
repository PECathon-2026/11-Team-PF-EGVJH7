import re

_CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
def find_cards(text: str):
    from .validators import luhn_ok
    out = []
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            out.append((m.start(), m.end(), m.group(0)))
    return out

_AADHAAR_RE = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")
def find_aadhaar(text: str):
    from .validators import verhoeff_ok
    out = []
    for m in _AADHAAR_RE.finditer(text):
        digits = re.sub(r"\s", "", m.group(0))
        if verhoeff_ok(digits):
            out.append((m.start(), m.end(), m.group(0)))
    return out

_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
def find_pan(text: str):
    return [(m.start(), m.end(), m.group(0)) for m in _PAN_RE.finditer(text)]

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
def find_email(text: str):
    return [(m.start(), m.end(), m.group(0)) for m in _EMAIL_RE.finditer(text)]

_PHONE_RE = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[\s().-]*)?(?:\(?\d{2,4}\)?[\s().-]*)?"
    r"\d{3,4}[\s().-]*\d{3,4}(?![\w\s().-]*\d)"
)
# Indian mobile numbers: optional +91 / 0091 / 0 prefix, then 10 digits
# starting 6-9, commonly grouped 5+5 ("+91 98765 43210"), which the generic
# pattern above cannot split. ASCII [0-9] keeps Python/JS parity exact.
_IN_MOBILE_RE = re.compile(
    r"(?<![\w+])(?:(?:\+|00)91[ -]?|0)?[6-9][0-9]{4}[ -]?[0-9]{5}(?!\w)"
)


def _isolated(text: str, start: int, end: int) -> bool:
    """Reject matches glued to more digits, e.g. inside card numbers."""
    if re.search(r"\d[\s().-]*$", text[:start]):
        return False
    return not re.match(r"^[\s().-]*\d", text[end:])


def find_phone(text: str):
    found = []
    for m in _PHONE_RE.finditer(text):
        if not _isolated(text, m.start(), m.end()):
            continue
        digits = re.sub(r"\D", "", m.group(0))
        formatted = bool(re.search(r"[+().\s-]", m.group(0)))
        if (10 <= len(digits) <= 15
                and (formatted or len(digits) == 10)
                and (len(digits) != 10 or digits[0] in "23456789")):
            found.append((m.start(), m.end(), m.group(0)))
    for m in _IN_MOBILE_RE.finditer(text):
        if _isolated(text, m.start(), m.end()):
            found.append((m.start(), m.end(), m.group(0)))

    # Merge both matchers: earliest start wins, then the longest span.
    out = []
    for start, end, raw in sorted(found, key=lambda hit: (hit[0], -hit[1])):
        if out and start < out[-1][1]:
            continue
        out.append((start, end, raw))
    return out

_OTP_DIGITS_RE = re.compile(r"\b\d{4,8}\b")
_OTP_CONTEXT = re.compile(r"(otp|one[-\s]?time|verification|2fa|code)", re.I)
def find_otp(text: str):
    if not _OTP_CONTEXT.search(text): return []
    return [(m.start(), m.end(), m.group(0)) for m in _OTP_DIGITS_RE.finditer(text)]

# FIXED: Added underscore and hyphen to the character class for sk- keys
_API_KEY_RE = re.compile(r"\b(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
def find_api_keys(text: str):
    return [(m.start(), m.end(), m.group(0)) for m in _API_KEY_RE.finditer(text)]

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
def find_ips(text: str):
    return [(m.start(), m.end(), m.group(0)) for m in _IP_RE.finditer(text)]
