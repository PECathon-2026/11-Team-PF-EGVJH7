from pathlib import Path
import re

import yaml


DEFAULT_RULES = {
    "always_redact_selectors": [],
    "never_redact": [],
}

PLACEHOLDERS = {
    "CARD": "[REDACTED:CARD]",
    "AADHAAR": "[REDACTED:AADHAAR]",
    "PAN": "[REDACTED:PAN]",
    "EMAIL": "[REDACTED:EMAIL]",
    "PHONE": "[REDACTED:PHONE]",
    "PASSWORD": "[REDACTED:PASSWORD]",
    "OTP": "[REDACTED:OTP]",
    "API_KEY": "[REDACTED:API_KEY]",
    "IP": "[REDACTED:IP]",
    "PERSON": "[REDACTED:PERSON]",
    "ADDRESS": "[REDACTED:ADDRESS]",
    "SECRET": "[REDACTED:SECRET]",
}


def normalize_type(value):
    """Normalize sensitive-data labels to canonical types."""
    if not value:
        return "SECRET"

    label = re.sub(
        r"[^A-Z0-9]+",
        "_",
        str(value).upper(),
    ).strip("_")

    aliases = {
        "CREDIT_CARD": "CARD",
        "CREDIT_CARD_NUMBER": "CARD",
        "CREDITCARD": "CARD",
        "CREDITCARDNUMBER": "CARD",
        "CARD_NUMBER": "CARD",
        "CC_NUMBER": "CARD",
        "AADHAR": "AADHAAR",
        "PHONE_NUMBER": "PHONE",
        "MOBILE": "PHONE",
        "IP_ADDRESS": "IP",
        "APIKEY": "API_KEY",
        "API_TOKEN": "API_KEY",
        "TOKEN": "API_KEY",
        "PASS": "PASSWORD",
        "PIN": "SECRET",
        "PERSON_NAME": "PERSON",
    }

    return aliases.get(label, label)


def placeholder_for(secret_type):
    """Return the placeholder for a sensitive-data type."""
    normalized = normalize_type(secret_type)

    return PLACEHOLDERS.get(
        normalized,
        f"[REDACTED:{normalized}]",
    )


def load_rules(path=None):
    """Load and validate the project's privacy rules."""
    if path is None:
        candidates = [
            Path(__file__).resolve().parents[2] / "rules.yaml",
            Path.cwd() / "rules.yaml",
        ]
        for candidate in candidates:
            if candidate.exists():
                path = str(candidate)
                break
        else:
            return {
                "always_redact_selectors": list(
                    DEFAULT_RULES["always_redact_selectors"]
                ),
                "never_redact": list(DEFAULT_RULES["never_redact"]),
            }

    rules_path = Path(path)

    if not rules_path.exists():
        raise FileNotFoundError(
            f"Privacy rules file not found: {rules_path}"
        )

    with rules_path.open("r", encoding="utf-8") as file:
        loaded = yaml.safe_load(file) or {}

    if not isinstance(loaded, dict):
        raise ValueError("Privacy rules must be a YAML mapping.")

    rules = {
        "always_redact_selectors": loaded.get(
            "always_redact_selectors",
            [],
        ),
        "never_redact": loaded.get(
            "never_redact",
            [],
        ),
    }

    for key, value in rules.items():
        if not isinstance(value, list):
            raise ValueError(f"'{key}' must be a list.")

        if not all(isinstance(item, str) for item in value):
            raise ValueError(
                f"Every item in '{key}' must be a string."
            )

    return rules


def matches_selector(element, selectors):
    """Check whether an element matches a configured CSS-like selector."""
    element_id = str(get_value(element, "id", "") or "")
    tag = str(get_value(element, "tag", "") or "").lower()

    attributes = get_value(element, "attributes", {}) or {}

    if not isinstance(attributes, dict):
        attributes = {}

    classes = str(
        attributes.get(
            "class",
            get_value(element, "class_name", ""),
        ) or ""
    ).split()

    for selector in selectors:
        selector = selector.strip()

        if not selector:
            continue

        if selector.startswith("#") and element_id == selector[1:]:
            return True

        if selector.startswith(".") and selector[1:] in classes:
            return True

        if selector.lower() == tag and tag:
            return True

        match = re.fullmatch(
            r""" \[\s*([a-zA-Z0-9_:-]+)\s*(?:=\s*["'](.*?)["']\s*)?\] """.strip(),
            selector,
        )

        if match:
            name, expected = match.groups()

            if name in attributes:
                actual = str(attributes[name])

                if expected is None or actual == expected:
                    return True

    return False


def get_value(obj, key, default=None):
    """Read a field from a dictionary or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)