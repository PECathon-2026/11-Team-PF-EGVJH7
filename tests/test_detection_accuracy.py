from core.detect.patterns import find_cards, find_email, find_otp, find_phone
from contracts.models import Element, PageSnapshot
from core.detect import detect
from core.sanitize import sanitize
from io import BytesIO
from PIL import Image


def test_edge_case_formats_and_near_misses():
    assert [row[2] for row in find_email(
        "edge.user+tag@example.test Mixed.Case@Example.Test"
    )] == ["edge.user+tag@example.test", "Mixed.Case@Example.Test"]
    assert [row[2] for row in find_phone("+44 (20) 7946 0958")] == [
        "+44 (20) 7946 0958"
    ]
    assert [row[2] for row in find_phone("9876543210")] == ["9876543210"]
    assert find_phone("12345") == []
    assert find_phone("202610300001") == []
    assert find_phone("4111 1111 1111 1112") == []
    assert [row[2] for row in find_cards(
        "4111 1111 1111 1111"
    )] == ["4111 1111 1111 1111"]
    assert find_cards("4111 1111 1111 1112") == []
    assert find_otp("Verification code: 804216")
    assert find_otp("Order number 202610300001") == []


def test_email_placeholder_is_detected_and_removed_from_sanitized_element():
    image = Image.new("RGB", (100, 50), "white")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    element = Element(
        id="e1", tag="input", placeholder="edge.user+tag@example.test",
        bbox={"x": 5, "y": 5, "w": 80, "h": 20},
    )
    snapshot = PageSnapshot(
        url="https://example.test", screenshot=buffer.getvalue(),
        viewport_size=(100, 50), elements=[element],
    )
    detections = detect(snapshot)
    assert any(hit.field == "placeholder" and hit.type == "EMAIL" for hit in detections)
    result = sanitize(snapshot, detections)
    assert "edge.user+tag@example.test" not in result.elements[0].placeholder
