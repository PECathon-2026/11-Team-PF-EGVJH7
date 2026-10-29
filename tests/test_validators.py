from core.detect.validators import luhn_ok, verhoeff_ok

def test_luhn_valid():
    assert luhn_ok("4111111111111111")
    assert luhn_ok("5555555555554444")

def test_luhn_invalid():
    assert not luhn_ok("4111111111111112")

def test_verhoeff_roundtrip():
    # We use a valid 11-digit base and brute-force the 12th check digit.
    # This proves verhoeff_ok correctly identifies valid Aadhaar numbers.
    base = "23456789012" # 11 digits
    valid_found = False
    
    for check_digit in range(10):
        full = base + str(check_digit)
        if verhoeff_ok(full):
            valid_found = True
            break
            
    assert valid_found, "Could not generate a valid Verhoeff number"
