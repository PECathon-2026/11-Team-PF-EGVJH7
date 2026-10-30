import pytest
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


@pytest.mark.parametrize("text, expected", [
    ("+91 98765 43210", "+91 98765 43210"),
    ("+91-98765-43210", "+91-98765-43210"),
    ("+91 9876543210", "+91 9876543210"),
    ("98765 43210", "98765 43210"),
    ("+919876543210", "+919876543210"),
    ("09876543210", "09876543210"),
    ("0091 98765 43210", "0091 98765 43210"),
    ("+91 98765-43210", "+91 98765-43210"),
    ("Call +91 98765 43210 today.", "+91 98765 43210"),
])
def test_indian_mobile_formats_are_detected_with_exact_offsets(text, expected):
    hits = find_phone(text)
    assert [raw for _, _, raw in hits] == [expected]
    start, end, raw = hits[0]
    assert text[start:end] == raw


@pytest.mark.parametrize("text", [
    "12345 67890",          # Indian mobiles start with 6-9
    "+91 12345 67890",
    "4111 98765 43210",     # glued to preceding digits (card-like)
    "98765 43210 99",       # glued to following digits
    "98765 432101",         # too many digits
    "98765  43210",         # double separator
    "order98765 43210",     # glued to a word
    "Order ID 58765-43210-7",
])
def test_indian_mobile_negatives(text):
    assert find_phone(text) == []


def test_indian_mobile_keeps_surrounding_text_offsets():
    text = "Ping me on +91 98765 43210 or mail a@b.co"
    [(start, end, raw)] = find_phone(text)
    assert (start, end) == (11, 26)
    assert text[:start] == "Ping me on " and text[end:] == " or mail a@b.co"


def test_labels_on_non_text_controls_are_not_secret_fields():
    from core.detect.structural import structural_hits

    def hits(**kwargs):
        return [d.type for d in structural_hits(Element(id="x", **kwargs))]

    assert hits(tag="input", type="checkbox", label="Show password", value="on") == []
    assert hits(tag="input", type="checkbox", label="Remember my email", value="on") == []
    assert hits(tag="button", type="button", text="Show password") == []
    assert hits(tag="a", text="Forgot password?", label="Forgot password?") == []
    assert hits(tag="input", type="radio", name="card_type", label="Credit card", value="credit") == []
    # Still detected:
    assert hits(tag="input", type="password", label="Password", value="hunter2") == ["PASSWORD"]
    assert "EMAIL" in hits(tag="input", type="email", label="Email", value="a@b.test")
    assert hits(tag="textarea", label="API key", value="abc123") == ["API_KEY"]
