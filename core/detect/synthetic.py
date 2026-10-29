import random
import re

# CACHE: Ensures repeated occurrences of the same entity resolve to the same synthetic value
_SYNTH_CACHE = {}

def generate_synthetic_card(real_card: str) -> str:
    clean_real = re.sub(r"[ -]", "", real_card)
    if len(clean_real) < 13: return real_card
    bin_prefix = clean_real[:6]
    middle_length = len(clean_real) - 7
    middle = "".join([str(random.randint(0, 9)) for _ in range(middle_length)])
    partial = bin_prefix + middle
    
    total = 0
    for i, ch in enumerate(reversed(partial)):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
            if n > 9: n -= 9
        total += n
    check_digit = (10 - (total % 10)) % 10
    synthetic_clean = partial + str(check_digit)
    
    if len(synthetic_clean) == 16:
        return f"{synthetic_clean[:4]} {synthetic_clean[4:8]} {synthetic_clean[8:12]} {synthetic_clean[12:]}"
    return synthetic_clean

def generate_synthetic_email(real_email: str) -> str:
    # PDF Rule: Use reserved example domains. Do not carry over real usernames.
    names = ["alex.smith", "jamie.doe", "taylor.jones", "jordan.lee"]
    fake_user = random.choice(names) + "_" + str(random.randint(100, 999))
    return f"{fake_user}@example.com"

def generate_synthetic_phone(real_phone: str) -> str:
    # PDF Rule: Preserve formatting, use safe test numbers
    return f"+91 9{random.randint(100000000, 999999999)}"

def generate_synthetic_name(real_name: str) -> str:
    first_names = ["John", "Jane", "Michael", "Sarah", "David", "Emma"]
    last_names = ["Doe", "Smith", "Johnson", "Williams", "Brown", "Jones"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"

def get_synthetic_value(det_type: str, real_value: str) -> str:
    # Master dispatcher. Ensures consistency across repeated calls.
    cache_key = f"{det_type}:{real_value}"
    if cache_key in _SYNTH_CACHE:
        return _SYNTH_CACHE[cache_key]

    generators = {
        "CARD": generate_synthetic_card,
        "EMAIL": generate_synthetic_email,
        "PHONE": generate_synthetic_phone,
        "PERSON": generate_synthetic_name,
    }
    
    generator = generators.get(det_type)
    if generator is None:
        raise ValueError(f"Unsupported sensitive-data type: {det_type}")
        
    synthetic_val = generator(real_value)
    _SYNTH_CACHE[cache_key] = synthetic_val
    return synthetic_val
