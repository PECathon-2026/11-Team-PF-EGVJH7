import random
import re

# CACHE: Ensures repeated occurrences of the same entity resolve to the same synthetic value
_SYNTH_CACHE = {}

def _luhn_check_digit(partial: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(partial)):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
            if n > 9: n -= 9
        total += n
    return str((10 - (total % 10)) % 10)


def generate_synthetic_card(real_card: str) -> str:
    clean_real = re.sub(r"[ -]", "", real_card)

    # CVV/CVC: same length, never the real value.
    if len(clean_real) <= 4:
        length = len(clean_real) or 3
        while True:
            fake = "".join(str(random.randint(0, 9)) for _ in range(length))
            if fake != clean_real:
                return fake

    if len(clean_real) < 13 or len(clean_real) > 19 or not clean_real.isdigit():
        return real_card

    # The number is generated independently of the real card: the first six
    # digits (BIN/IIN) identify the issuing bank, so they are never reused.
    while True:
        partial = "4" + "".join(str(random.randint(0, 9)) for _ in range(len(clean_real) - 2))
        synthetic_clean = partial + _luhn_check_digit(partial)
        if synthetic_clean[:6] != clean_real[:6] and synthetic_clean != clean_real:
            break

    # Keep the original layout (spaces/dashes) so the page context still reads naturally.
    digits = iter(synthetic_clean)
    return re.sub(r"\d", lambda _: next(digits), real_card)

def generate_synthetic_email(real_email: str) -> str:
    names = ["alex.smith", "jamie.doe", "taylor.jones", "jordan.lee"]
    fake_user = random.choice(names) + "_" + str(random.randint(100, 999))
    return f"{fake_user}@example.com"

def generate_synthetic_phone(real_phone: str) -> str:
    return f"+91 9{random.randint(100000000, 999999999)}"

def generate_synthetic_name(real_name: str) -> str:
    first_names = ["John", "Jane", "Michael", "Sarah", "David", "Emma"]
    last_names = ["Doe", "Smith", "Johnson", "Williams", "Brown", "Jones"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"

def generate_synthetic_address(real_address: str) -> str:
    return f"{random.randint(10, 999)} Synthetic Avenue, Test City"

def get_synthetic_value(det_type: str, real_value: str) -> str:
    cache_key = f"{det_type}:{real_value}"
    if cache_key in _SYNTH_CACHE:
        return _SYNTH_CACHE[cache_key]

    generators = {
        "CARD": generate_synthetic_card,
        "EMAIL": generate_synthetic_email,
        "PHONE": generate_synthetic_phone,
        "PERSON": generate_synthetic_name,
        "ADDRESS": generate_synthetic_address,
    }
    
    generator = generators.get(det_type)
    if generator is None:
        raise ValueError(f"Unsupported sensitive-data type: {det_type}")
        
    synthetic_val = generator(real_value)
    _SYNTH_CACHE[cache_key] = synthetic_val
    return synthetic_val
