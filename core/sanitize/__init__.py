"""Privacy sanitization pipeline for webpage snapshots."""

import copy
import hashlib
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Optional

from PIL import Image

from contracts.models import Detection, Element, PageSnapshot
from core.sanitize.image import redact_image
from core.sanitize.injection import scan_page_elements
from core.sanitize.rules import (
    load_rules,
    matches_selector,
    normalize_type,
    placeholder_for,
)
from core.sanitize.text import sanitize_elements


@dataclass
class SanitizedView:
    """A sanitized webpage snapshot ready for downstream processing."""

    url: str
    title: str
    screenshot: bytes
    screenshot_sha256: str
    elements: list[Element]
    report: list[dict[str, Any]]


def get_value(obj: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dictionary or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


def bbox_to_dict(bbox: Any) -> Optional[dict[str, float]]:
    """Convert a bounding box into the format expected by image redaction."""
    if bbox is None:
        return None

    if isinstance(bbox, dict):
        values = bbox
    elif hasattr(bbox, "model_dump"):
        values = bbox.model_dump()
    elif hasattr(bbox, "dict"):
        values = bbox.dict()
    else:
        values = {
            "x": get_value(bbox, "x"),
            "y": get_value(bbox, "y"),
            "w": get_value(bbox, "w"),
            "h": get_value(bbox, "h"),
        }

    try:
        result = {
            "x": float(values["x"]),
            "y": float(values["y"]),
            "w": float(values["w"]),
            "h": float(values["h"]),
        }
    except (KeyError, TypeError, ValueError):
        return None

    if result["w"] <= 0 or result["h"] <= 0:
        return None

    return result


def element_attributes(element: Any) -> dict:
    """Get an element's HTML attributes using the project's supported fields."""
    attrs = get_value(element, "attrs", None)

    if not isinstance(attrs, dict):
        attrs = get_value(element, "attributes", None)

    return attrs if isinstance(attrs, dict) else {}


def selector_matches(element: Any, selectors: list[str]) -> bool:
    """Match an element against the project's configured CSS selectors."""
    if not selectors:
        return False

    # The project's selector matcher reads the 'attributes' field.
    # Make a shallow copy when the original element uses 'attrs' instead.
    attrs = element_attributes(element)

    if isinstance(element, dict):
        candidate = dict(element)
        candidate["attributes"] = attrs
    else:
        candidate = copy.copy(element)

        try:
            setattr(candidate, "attributes", attrs)
        except (AttributeError, TypeError):
            pass

    return matches_selector(candidate, selectors)


def make_detection(
    element: Any,
    detection_type: str,
    reason: str,
) -> Detection:
    """Create a detection compatible with the existing model."""
    element_id = str(get_value(element, "id", "") or "")
    bbox = bbox_to_dict(get_value(element, "bbox"))

    detection_data = {
        "type": normalize_type(detection_type),
        "source": "custom_rule",
        "element_id": element_id,
        "field": "value",
        "span": None,
    }

    if bbox is not None:
        detection_data["bbox"] = bbox

    detection = Detection(**detection_data)

    # Preserve the reason in a separate attribute only if the model supports it.
    # The custom-rule report below also records the reason.
    return detection


def apply_project_rules(
    elements: list[Element],
    detections: list[Any],
    rules: dict,
) -> tuple[list[Any], list[dict[str, Any]]]:
    """
    Apply always_redact_selectors and never_redact from rules.yaml.

    Elements matched by never_redact are excluded from the existing detections.
    Elements matched by always_redact_selectors receive a SECRET detection.
    """
    always_selectors = rules.get("always_redact_selectors", [])
    never_selectors = rules.get("never_redact", [])

    elements_by_id = {
        str(get_value(element, "id", "")): element
        for element in elements
        if get_value(element, "id")
    }

    protected_ids = set()
    always_redact_ids = set()

    for element in elements:
        element_id = str(get_value(element, "id", "") or "")

        if not element_id:
            continue

        if selector_matches(element, never_selectors):
            protected_ids.add(element_id)

        if selector_matches(element, always_selectors):
            always_redact_ids.add(element_id)

    # Explicit never_redact rules take precedence over automatic detections.
    filtered_detections = [
        detection
        for detection in detections
        if str(get_value(detection, "element_id", "") or "")
        not in protected_ids
    ]

    existing = {
        (
            str(get_value(detection, "element_id", "") or ""),
            normalize_type(get_value(detection, "type", "SECRET")),
        )
        for detection in filtered_detections
    }

    rule_report = []

    for element_id in sorted(always_redact_ids):
        key = (element_id, "SECRET")

        if key in existing:
            continue

        element = elements_by_id[element_id]
        detection = make_detection(element, "SECRET", "Matched always_redact_selectors")

        filtered_detections.append(detection)

        rule_report.append({
            "element_id": element_id,
            "type": "SECRET",
            "field": "value",
            "reason": "Element matched an always_redact_selectors rule.",
            "placeholder": placeholder_for("SECRET"),
        })

    for element_id in sorted(protected_ids):
        rule_report.append({
            "element_id": element_id,
            "type": "NEVER_REDACT",
            "reason": "Element matched a never_redact rule; automatic detections were skipped.",
        })

    return filtered_detections, rule_report


def resolve_detection_bboxes(
    elements: list[Element],
    detections: list[Any],
) -> list[Any]:
    """Fill missing detection geometry from its corresponding snapshot element."""
    elements_by_id = {
        str(get_value(element, "id", "")): element
        for element in elements
        if get_value(element, "id")
    }

    for detection in detections:
        if get_value(detection, "bbox") is not None:
            continue

        element_id = str(
            get_value(detection, "element_id", "") or ""
        )

        element = elements_by_id.get(element_id)

        if element is None:
            continue

        bbox = bbox_to_dict(get_value(element, "bbox"))

        if bbox is None:
            continue

        try:
            if isinstance(detection, dict):
                detection["bbox"] = bbox
            else:
                detection.bbox = bbox
        except (AttributeError, TypeError, ValueError):
            # If the detection model rejects assignment, leave it unchanged.
            # Image redaction will report any unusable geometry.
            continue

    return detections


def validate_image(image_bytes: bytes, description: str) -> None:
    """Raise a useful error if the provided image bytes are invalid."""
    if not isinstance(image_bytes, bytes) or not image_bytes:
        raise ValueError(f"{description} must be non-empty image bytes.")

    try:
        with Image.open(BytesIO(image_bytes)) as image:
            image.load()
    except Exception as exc:
        raise ValueError(f"{description} is not a valid readable image.") from exc


def sanitize(
    snapshot: PageSnapshot,
    detections: list[Any],
    rules_path: Optional[str] = None,
) -> SanitizedView:
    """
    Sanitize DOM data and redact sensitive regions from the screenshot.

    This function preserves the original snapshot and detections by working
    with deep copies. It uses the project's actual injection scanner,
    privacy-rule helpers, text sanitizer, and image-redaction function.
    """
    if snapshot is None:
        raise ValueError("A page snapshot is required.")

    validate_image(snapshot.screenshot, "Snapshot screenshot")

    # Avoid mutating the caller's snapshot or detection objects.
    elements = copy.deepcopy(snapshot.elements or [])
    working_detections = copy.deepcopy(detections or [])

    # Load the configured rules and apply their supported selector options.
    rules = load_rules(rules_path)

    working_detections, rule_report = apply_project_rules(
        elements,
        working_detections,
        rules,
    )

    # Populate bounding boxes before redacting the screenshot.
    resolve_detection_bboxes(elements, working_detections)

    # Use the actual function exported by core.sanitize.injection.
    injection_report = scan_page_elements(elements)

    # Sanitize sensitive values in DOM elements.
    sanitized_elements, text_report = sanitize_elements(
        elements,
        working_detections,
    )

    # redact_image returns a tuple:
    # (sanitized_png_bytes, image_redaction_report)
    sanitized_screenshot, image_report = redact_image(
        snapshot.screenshot,
        working_detections,
    )

    validate_image(sanitized_screenshot, "Sanitized screenshot")

    screenshot_sha256 = hashlib.sha256(
        sanitized_screenshot
    ).hexdigest()

    report = []
    report.extend(text_report or [])
    report.extend(image_report or [])
    report.extend(injection_report or [])
    report.extend(rule_report or [])

    return SanitizedView(
        url=snapshot.url,
        title=snapshot.title,
        screenshot=sanitized_screenshot,
        screenshot_sha256=screenshot_sha256,
        elements=sanitized_elements,
        report=report,
    )