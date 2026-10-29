
"""Redact sensitive screenshot regions using solid black rectangles."""

from io import BytesIO

from PIL import Image, ImageDraw


def get_value(obj, key, default=None):
    """Read a value from a dictionary or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def get_bbox(detection):
    """Extract finite, positive-area geometry without unsafe conversions."""
    bbox = get_value(detection, "bbox")

    if bbox is None:
        return None

    keys = ("x", "y", "w", "h")

    if isinstance(bbox, dict):
        if any(key not in bbox for key in keys):
            raise ValueError("Bounding box is missing coordinates.")
        values = tuple(bbox[key] for key in keys)
    else:
        values = tuple(get_value(bbox, key) for key in keys)

    import math

    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        for value in values
    ):
        raise ValueError("Bounding box contains invalid or non-finite coordinates.")

    x, y, w, h = values

    if w <= 0 or h <= 0:
        raise ValueError("Bounding box dimensions must be positive.")
    if not math.isfinite(x + w) or not math.isfinite(y + h):
        raise ValueError("Bounding box edges exceed finite coordinate range.")

    return x, y, w, h


def redact_image(image_bytes, detections):
    """
    Redact detected regions with opaque black rectangles.

    Returns:
        (sanitized_png_bytes, redaction_report)
    """
    if not isinstance(image_bytes, bytes) or not image_bytes:
        raise ValueError("A non-empty screenshot in bytes is required.")

    try:
        with Image.open(BytesIO(image_bytes)) as original:
            image = original.convert("RGB")
    except Exception as exc:
        raise ValueError("Unable to read the screenshot.") from exc

    draw = ImageDraw.Draw(image)
    image_width, image_height = image.size
    report = []

    for detection in detections or []:
        element_id = str(get_value(detection, "element_id", "") or "")
        dtype = str(get_value(detection, "type", "SECRET"))
        try:
            bbox = get_bbox(detection)
        except (TypeError, ValueError, OverflowError) as exc:
            report.append({"element_id": element_id, "type": dtype,
                           "status": "failed", "reason": str(exc)})
            continue

        if bbox is None:
            report.append({"element_id": element_id, "type": dtype,
                           "status": "skipped", "reason": "No image bounding box is available."})
            continue

        x, y, w, h = bbox
        import math

        # Boxes are viewport-relative CSS pixels; Playwright screenshots use
        # CSS scale. Clip partial intersections, but never invent offscreen pixels.
        left = max(0, math.floor(x))
        top = max(0, math.floor(y))
        right = min(image_width - 1, math.ceil(x + w) - 1)
        bottom = min(image_height - 1, math.ceil(y + h) - 1)

        if right < left or bottom < top:
            report.append({"element_id": element_id, "type": dtype,
                           "status": "skipped", "reason": "Bounding box is outside the captured screenshot."})
            continue

        # Solid black: no blur or transparency.
        draw.rectangle(
            (left, top, right, bottom),
            fill=(0, 0, 0),
        )

        report.append({
            "element_id": element_id,
            "type": dtype,
            "status": "redacted",
            "bbox": {
                "x": left,
                "y": top,
                "w": right - left + 1,
                "h": bottom - top + 1,
            },
            "reason": (
                "Sensitive screenshot region covered "
                "with an opaque black rectangle."
            ),
        })

    output = BytesIO()
    image.save(output, format="PNG")

    return output.getvalue(), report
