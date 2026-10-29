
"""Public entry point for PrivacyLens page sanitization."""

from copy import deepcopy
from hashlib import sha256
from io import BytesIO
from math import isfinite

from PIL import Image

from contracts.models import SanitizedView
from .image import redact_image
from .injection import scan_page_elements
from .rules import load_rules, matches_selector, normalize_type
from .text import sanitize_elements


def _get(obj, key, default=None):
    """Read a value from a dictionary or a dataclass."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _validate_image_detections(detections, image_size):
    """Reject malformed or out-of-bounds bounding boxes."""
    width, height = image_size

    for detection in detections:
        raw_bbox = _get(detection, "bbox")

        # Missing bounding boxes are permitted for text-only detections.
        if raw_bbox is None:
            continue

        if isinstance(raw_bbox, dict):
            keys = ("x", "y", "w", "h")
            if any(key not in raw_bbox for key in keys):
                raise ValueError(
                    "Sanitization failed: bounding box is missing coordinates."
                )
            values = tuple(raw_bbox[key] for key in keys)
        else:
            raise ValueError(
                "Sanitization failed: bounding box must be a dictionary."
            )

        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not isfinite(value)
            for value in values
        ):
            raise ValueError(
                "Sanitization failed: bounding box has invalid coordinates."
            )

        x, y, w, h = values

        if w <= 0 or h <= 0:
            raise ValueError(
                "Sanitization failed: bounding box dimensions must be positive."
            )

        if x < 0 or y < 0 or x + w > width or y + h > height:
            raise ValueError(
                "Sanitization failed: bounding box extends outside the screenshot."
            )


def _apply_custom_rules(elements, detections, selectors, exclusions=None):
    """
    Apply custom privacy rules.

    Exclusions affect custom rules only. They never remove detections
    already supplied by the privacy detector.
    """
    exclusions = exclusions or []

    for element in elements:
        if not matches_selector(element, selectors):
            continue

        if matches_selector(element, exclusions):
            continue

        element_id = str(_get(element, "id", "") or "")
        bbox = _get(element, "bbox")

        fields = []
        for field_name in ("text", "value", "label", "placeholder", "title"):
            value = _get(element, field_name)
            if isinstance(value, str) and value:
                fields.append(field_name)

        if not fields:
            continue

        # A matching sensitive element must not silently leave its
        # corresponding screenshot region unprotected.
        if bbox is None:
            raise ValueError(
                "Sanitization failed: a custom-rule match contains text "
                "but has no bounding box for screenshot redaction."
            )

        for field_name in fields:
            detections.append(
                {
                    "element_id": element_id,
                    "field": field_name,
                    "type": "SECRET",
                    "span": None,
                    "bbox": bbox,
                    "source": "custom_privacy_rule",
                }
            )


def sanitize(snapshot, detections, rules_path=None):
    """
    Return a sanitized view of a captured webpage.

    The input snapshot is not modified. Invalid screenshots and malformed
    visual detection geometry cause sanitization to fail rather than
    silently returning unsafe image data.
    """
    screenshot = _get(snapshot, "screenshot")
    original_elements = _get(snapshot, "elements", [])

    if not isinstance(screenshot, bytes) or not screenshot:
        raise ValueError(
            "Sanitization failed: screenshot bytes are missing."
        )

    if original_elements is None:
        original_elements = []

    if not isinstance(original_elements, (list, tuple)):
        raise ValueError(
            "Sanitization failed: snapshot elements must be a list."
        )

    elements = deepcopy(list(original_elements))
    all_detections = list(detections or [])

    rules = load_rules(rules_path)

    _apply_custom_rules(
        elements,
        all_detections,
        rules["always_redact_selectors"],
        rules["never_redact"],
    )

    # Record suspicious webpage instructions as untrusted content.
    injection_findings = scan_page_elements(elements)

    # Sanitize text fields on copied elements.
    sanitized_elements, text_records = sanitize_elements(
        elements,
        all_detections,
    )

    # Validate that the screenshot can be decoded before processing.
    try:
        with Image.open(BytesIO(screenshot)) as image:
            image.load()
            image_size = image.size
    except Exception as exc:
        raise ValueError(
            "Sanitization failed: screenshot cannot be decoded."
        ) from exc

    _validate_image_detections(all_detections, image_size)

    sanitized_screenshot, image_records = redact_image(
        screenshot,
        all_detections,
    )

    report = []

    for record in text_records:
        report.append(
            {
                "element_id": record.element_id,
                "field": record.field,
                "type": normalize_type(record.secret_type),
                "placeholder": record.placeholder,
                "reason": record.reason,
            }
        )

    report.extend(image_records)

    for finding in injection_findings:
        report.append(
            {
                "element_id": finding["element_id"],
                "field": finding["field"],
                "type": "PROMPT_INJECTION",
                "placeholder": "[FLAGGED:INJECTION]",
                "reason": finding["reason"],
                "category": finding["category"],
            }
        )

    screenshot_hash = sha256(sanitized_screenshot).hexdigest()

    return SanitizedView(
        url=_get(snapshot, "url", "") or "",
        title=_get(snapshot, "title", "") or "",
        screenshot=sanitized_screenshot,
        elements=sanitized_elements,
        screenshot_sha256=screenshot_hash,
        report=report,
    )


__all__ = ["sanitize", "SanitizedView"]
