
from contracts.models import GuardResult
from core.detect import scan_text


MAX_DEPTH = 30


def _collect_strings(payload, depth=0):
    """Collect strings recursively without serializing arbitrary objects."""
    if depth > MAX_DEPTH:
        raise ValueError("Payload nesting limit exceeded.")

    if payload is None or isinstance(payload, (bool, int, float)):
        return []

    if isinstance(payload, str):
        return [payload]

    if isinstance(payload, dict):
        strings = []
        for key, value in payload.items():
            if not isinstance(key, str):
                raise ValueError("Payload contains a non-string key.")
            strings.append(key)
            strings.extend(_collect_strings(value, depth + 1))
        return strings

    if isinstance(payload, (list, tuple)):
        strings = []
        for item in payload:
            strings.extend(_collect_strings(item, depth + 1))
        return strings

    raise ValueError("Payload contains an unsupported data type.")


def check_egress(payload) -> GuardResult:
    """
    Block outgoing payloads when sensitive data is detected
    or the payload cannot be safely inspected.
    """
    try:
        strings = _collect_strings(payload)
        detections = scan_text("\n".join(strings))

        if detections:
            types_found = sorted({d.type for d in detections})
            return GuardResult(
                ok=False,
                reasons=[
                    "Sensitive data detected in outgoing payload: "
                    + ", ".join(types_found)
                ],
            )

        return GuardResult(ok=True)

    except Exception:
        # Fail closed; never include payload contents in the error.
        return GuardResult(
            ok=False,
            reasons=["Egress scan failed; outgoing payload blocked."],
        )
