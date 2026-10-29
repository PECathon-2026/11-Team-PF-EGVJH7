from contracts.models import PageSnapshot, Detection
from .patterns import (
    find_cards, find_aadhaar, find_pan, find_email, find_phone, find_otp,
    find_api_keys, find_ips
)
from .structural import structural_hits
from .merge import merge_detections, calculate_mosaic_risk

_FINDERS = [
    ("CARD", find_cards), ("AADHAAR", find_aadhaar), ("PAN", find_pan),
    ("EMAIL", find_email), ("PHONE", find_phone), ("OTP", find_otp),
    ("API_KEY", find_api_keys), ("IP", find_ips)
]

def scan_text(text: str) -> list[Detection]:
    out = []
    for dtype, fn in _FINDERS:
        for start, end, _raw in fn(text):
            out.append(Detection(type=dtype, source="regex", field="value", span=(start, end)))
    return out

def detect(snapshot: PageSnapshot) -> list[Detection]:
    raw = []
    for el in snapshot.elements:
        raw.extend(structural_hits(el))
        for field in ("text", "value", "label", "placeholder"):
            content = getattr(el, field, "") or ""
            if not content: continue
            for dtype, fn in _FINDERS:
                for start, end, _raw in fn(content):
                    raw.append(Detection(
                        type=dtype, source="regex", element_id=el.id, field=field, span=(start, end),
                        bbox=el.bbox
                    ))
                    
    merged = merge_detections(raw)
    risk = calculate_mosaic_risk(merged)
    if risk > 10.0:
        print(f"🚨 [P2 WARNING] HIGH MOSAIC RISK DETECTED ({risk}). Multiple identity factors found!")
    else:
        print(f"✅ [P2] Mosaic Risk Score: {risk}")
        
    return merged
