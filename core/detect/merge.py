import math
from contracts.models import Detection

_TYPE_PRIORITY = {"CARD": 3, "AADHAAR": 3, "PAN": 3, "PASSWORD": 3, "OTP": 3, "API_KEY": 3, "EMAIL": 2, "PHONE": 2, "IP": 2, "OTHER": 1, "FACE": 1, "PERSON": 1, "ADDRESS": 1}

_RISK_WEIGHTS = {
    "CARD": 10, "AADHAAR": 10, "PAN": 10, "PASSWORD": 10, "API_KEY": 10,
    "EMAIL": 3, "PHONE": 3, "ADDRESS": 3, "PERSON": 2, "IP": 2
}

def merge_detections(dets: list[Detection]) -> list[Detection]:
    buckets = {}
    for d in dets:
        buckets.setdefault((d.element_id, d.field), []).append(d)

    merged = []
    for group in buckets.values():
        whole = [d for d in group if d.span is None]
        spans = [d for d in group if d.span is not None]

        if whole:
            best = max(whole, key=lambda d: _TYPE_PRIORITY.get(d.type, 0))
            best.confidence = min(1.0, 0.5 + 0.25 * len({d.source for d in whole}))
            merged.append(best)
            continue

        spans.sort(key=lambda d: (d.span[0], -d.span[1]))
        kept = []
        for d in spans:
            overlap = False
            for k in kept:
                if d.span[0] < k.span[1] and k.span[0] < d.span[1]:
                    overlap = True
                    if _TYPE_PRIORITY.get(d.type, 0) > _TYPE_PRIORITY.get(k.type, 0): k.type = d.type
                    k.confidence = min(1.0, k.confidence + 0.15)
                    break
            if not overlap: kept.append(d)
        merged.extend(kept)

    return merged

def calculate_mosaic_risk(merged_dets: list[Detection]) -> float:
    if not merged_dets:
        return 0.0
    base_risk = sum(math.sqrt(_RISK_WEIGHTS.get(d.type, 1) * d.confidence) for d in merged_dets)
    density = len(merged_dets)
    density_penalty = 0.5 * math.exp(density / 5.0)
    return round(base_risk + density_penalty, 2)
