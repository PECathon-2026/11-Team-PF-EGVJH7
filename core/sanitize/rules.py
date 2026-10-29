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
    """Normalize sensitive-data labels."""
    if not value:
        return "SECRET"

    label = re.sub(
        r"[^A-Z0-9]+",
        "_",
        str(value).upper()
    ).strip("_")

    aliases = {
        "CREDIT_CARD": "CARD",
        "CARD_NUMBER": "CARD",
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
        f"[REDACTED:{normalized}]"
    )


def load_rules(path=None):
    """Load and validate the project's privacy rules."""
    if path is None:
        path = Path(__file__).resolve().parents[2] / "rules.yaml"
    else:
        path = Path(path)

    if not path.exists():
        return DEFAULT_RULES.copy()

    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Invalid privacy rules YAML: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            "Privacy rules must be a YAML mapping."
        )

    result = DEFAULT_RULES.copy()

    for key in result:
        value = data.get(key, [])

        if not isinstance(value, list):
            raise ValueError(
                f"'{key}' must be a list."
            )

        if not all(isinstance(item, str) for item in value):
            raise ValueError(
                f"Every entry in '{key}' must be a string."
            )

        result[key] = value

    return result


def matches_selector(element, selectors):
    """Match basic CSS selectors against webpage elements."""
    def get_value(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)

        return getattr(obj, key, default)

    element_id = str(get_value(element, "id", "") or "")
    tag = str(get_value(element, "tag", "") or "").lower()

    attributes = get_value(element, "attributes", {}) or {}

    if not isinstance(attributes, dict):
        attributes = {}

    classes = str(
        attributes.get(
            "class",
            get_value(element, "class_name", "")
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
            r"""\[\s*([a-zA-Z0-9_:-]+)\s*(?:=\s*["'](.*?)["']\s*)?\]""",
            selector,
        )

        if match:
            name, expected = match.groups()

            if name in attributes:
                actual = str(attributes[name])

                if expected is None or actual == expected:
                    return True

    return False