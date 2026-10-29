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

_PHONE_RE = re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b")
def find_phone(text: str):
    return [(m.start(), m.end(), m.group(0)) for m in _PHONE_RE.finditer(text)]

_OTP_DIGITS_RE = re.compile(r"\b\d{4,8}\b")
_OTP_CONTEXT = re.compile(r"(otp|one[-\s]?time|verification|2fa|code)", re.I)
def find_otp(text: str):
    if not _OTP_CONTEXT.search(text): return []
    return [(m.start(), m.end(), m.group(0)) for m in _OTP_DIGITS_RE.finditer(text)]

# --- Phase 2 Additions: API Keys, JWT, IPs ---
_API_KEY_RE = re.compile(r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
def find_api_keys(text: str):
    return [(m.start(), m.end(), m.group(0)) for m in _API_KEY_RE.finditer(text)]

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
def find_ips(text: str):
    return [(m.start(), m.end(), m.group(0)) for m in _IP_RE.finditer(text)]
