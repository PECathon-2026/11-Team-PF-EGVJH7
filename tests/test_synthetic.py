import pytest
import re
from core.detect.synthetic import (
    get_synthetic_value, 
    generate_synthetic_card, 
    generate_synthetic_email
)
from core.detect.validators import luhn_ok

def test_card_luhn_and_length():
    real = "4111 1111 1111 1111"
    fake = generate_synthetic_card(real)
    clean_fake = re.sub(r"[ -]", "", fake)
    assert len(clean_fake) == 16
    assert luhn_ok(clean_fake), "Synthetic card failed Luhn check!"
    assert fake != real, "Synthetic card is identical to real card"

def test_email_syntax_and_domain():
    real = "john.doe@company.com"
    fake = generate_synthetic_email(real)
    assert "@example.com" in fake
    assert re.match(r"^[\w\.-]+@example\.com$", fake), "Synthetic email format invalid"

def test_repeated_entity_consistency():
    real = "alice@example.com"
    fake1 = get_synthetic_value("EMAIL", real)
    fake2 = get_synthetic_value("EMAIL", real)
    assert fake1 == fake2, "Cache failed: same real value produced different synthetic values"

def test_unsupported_type_raises_error():
    with pytest.raises(ValueError, match="Unsupported sensitive-data type"):
        get_synthetic_value("UNKNOWN_TYPE", "12345")

def test_malformed_input_fails_safely():
    # Malformed card (too short) should return the original, not crash
    real = "123"
    fake = generate_synthetic_card(real)
    assert fake == real, "Malformed input did not fail safely"

def test_collision_handling():
    # Two different real cards should generate two different fake cards
    real1 = "4111 1111 1111 1111"
    real2 = "5555 5555 5555 4444"
    fake1 = get_synthetic_value("CARD", real1)
    fake2 = get_synthetic_value("CARD", real2)
    assert fake1 != fake2, "Collision detected: two different real cards mapped to the same fake card"
