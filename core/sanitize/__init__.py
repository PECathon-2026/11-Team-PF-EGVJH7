
from copy import deepcopy
from hashlib import sha256
from dataclasses import dataclass, field
from io import BytesIO
import math

from PIL import Image

from .image import redact_image
from .injection import scan_page_elements
from .rules import load_rules, matches_selector
from .text import sanitize_elements


@dataclass
class SanitizedView:
    """Sanitized representation of a webpage."""
    url: str
    title: str
    screenshot: bytes
    elements: list
    screenshot_sha256: str
    report: list = field(default_factory=list)


def get_value(obj, key, default=None):
    """Read data from a dictionary or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)



def make_full_field_detection(element, field, secret_type):
    """Create a detection that redacts the entire matching field."""
    return {
        "element_id": str(get_value(element, "id", "")),
        "field": field,
        "type": secret_type,
        "source": "custom_privacy_rule",
        "span": None,
        "bbox": get_value(element, "bbox"),
    }


def validate_image_detections(detections, image_size):
    """Reject malformed or out-of-bounds bounding boxes."""
    width, height = image_size

    for detection in detections:
        bbox = get_value(detection, "bbox")

        # Bounding boxes are optional for text-only detections.
        if bbox is None:
            continue

        keys = ("x", "y", "w", "h")

        if isinstance(bbox, dict):
            if any(key not in bbox for key in keys):
                raise ValueError(
                    "Sanitization failed: bounding box is missing coordinates."
                )
            values = [bbox[key] for key in keys]

        elif all(hasattr(bbox, key) for key in keys):
            values = [getattr(bbox, key) for key in keys]

        else:
            raise ValueError(
                "Sanitization failed: invalid bounding box."
            )

        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in values
        ):
            raise ValueError(
                "Sanitization failed: bounding box coordinates must be finite numbers."
            )

        x, y, w, h = values

        if (
            x < 0
            or y < 0
            or w <= 0
            or h <= 0
            or x + w > width
            or y + h > height
        ):
            raise ValueError(
                "Sanitization failed: bounding box is invalid or out of bounds."
            )


def sanitize(snapshot, detections, rules_path=None):
    """
    Sanitize a webpage snapshot before it is included in an AI request.

    Returns:
        SanitizedView containing the sanitized screenshot, elements,
        screenshot hash, and a redaction/security report.

    Raises:
        ValueError: If the screenshot or bounding boxes are invalid.
    """
    screenshot = get_value(snapshot, "screenshot")
    original_elements = get_value(snapshot, "elements", [])

    if not isinstance(screenshot, bytes) or not screenshot:
        raise ValueError(
            "Sanitization failed: screenshot bytes are missing."
        )

    if original_elements is None:
        original_elements = []

    # Validate the screenshot before processing it.
    try:
        with Image.open(BytesIO(screenshot)) as image:
            image_size = image.size
            image.verify()
    except Exception as exc:
        raise ValueError(
            "Sanitization failed: screenshot is not a valid image."
        ) from exc

    # Preserve the caller's original elements.
    elements = deepcopy(list(original_elements))
    detections = list(detections or [])

    # Load configured privacy rules.
    rules = load_rules(rules_path)

    # Apply mandatory custom privacy selectors.
    for element in elements:
        if matches_selector(
            element,
            rules["always_redact_selectors"],
        ):
            for field_name in ("text", "value", "label"):
                value = get_value(element, field_name)

                if isinstance(value, str) and value:
                    detections.append(
                        make_full_field_detection(
                            element,
                            field_name,
                            "SECRET",
                        )
                    )

    # Flag prompt injection before modifying page text.
    injection_findings = scan_page_elements(elements)

    # Validate bounding boxes before any image redaction.
    validate_image_detections(detections, image_size)

    # Sanitize sensitive text and field values.
    sanitized_elements, text_report = sanitize_elements(
        elements,
        detections,
    )

    # Redact sensitive image regions.
    sanitized_screenshot, image_report = redact_image(
        screenshot,
        detections,
    )

    # Build a report without including original secret values.
    report = []

    for record in text_report:
        report.append(
            {
                "element_id": record.element_id,
                "field": record.field,
                "type": record.secret_type,
                "placeholder": record.placeholder,
                "reason": record.reason,
            }
        )

    report.extend(image_report)

    # Record prompt-injection findings without copying suspicious text.
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

    # Hash the exact sanitized screenshot bytes.
    screenshot_hash = sha256(sanitized_screenshot).hexdigest()

    url = get_value(snapshot, "url", "") or ""
    title = get_value(snapshot, "title", "") or ""

    return SanitizedView(
        url=url,
        title=title,
        screenshot=sanitized_screenshot,
        elements=sanitized_elements,
        screenshot_sha256=screenshot_hash,
        report=report,
    )


__all__ = ["sanitize", "SanitizedView"]