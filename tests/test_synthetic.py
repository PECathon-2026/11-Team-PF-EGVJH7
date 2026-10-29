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
    
    # Check length and Luhn
    assert len(clean_fake) == 16
    assert luhn_ok(clean_fake), "Synthetic card failed Luhn check!"
    assert fake != real, "Synthetic card is identical to real card"

def test_email_syntax_and_domain():
    real = "john.doe@company.com"
    fake = generate_synthetic_email(real)
    
    # Check domain and syntax
    assert "@example.com" in fake
    assert re.match(r"^[\w\.-]+@example\.com$", fake), "Synthetic email format invalid"

def test_repeated_entity_consistency():
    # PDF Rule: Repeated occurrences should resolve to the same synthetic value
    real = "alice@example.com"
    fake1 = get_synthetic_value("EMAIL", real)
    fake2 = get_synthetic_value("EMAIL", real)
    assert fake1 == fake2, "Cache failed: same real value produced different synthetic values"

def test_unsupported_type_raises_error():
    # PDF Rule: Controlled error for unsupported types
    with pytest.raises(ValueError, match="Unsupported sensitive-data type"):
        get_synthetic_value("UNKNOWN_TYPE", "12345")
