"""Conservative URL policy shared by action validation and execution."""

import re
from urllib.parse import parse_qsl, unquote, urlparse


RISKY_OPERATIONS = re.compile(
    r"(?:^|[^a-z0-9])(?:delete|remove|submit|purchase|buy|transfer|pay|"
    r"logout|logoff|cancel|destroy|deactivate|withdraw|refund)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
RISKY_QUERY_KEYS = {"action", "operation", "op", "intent", "command", "cmd", "do", "method"}


def validate_navigation_url(url: str) -> str:
    """Accept ordinary HTTP(S) URLs and reject consequential destinations."""
    if not isinstance(url, str) or not url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("Navigation URL is malformed.")
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        raise ValueError("Navigation URL is malformed.") from None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Navigation is restricted to HTTP(S) URLs with a hostname.")
    if parsed.username is not None or parsed.password is not None or (port is not None and not 1 <= port <= 65535):
        raise ValueError("Navigation URL contains unsupported authority data.")

    components = [parsed.path, parsed.fragment]
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    components.extend(part for pair in pairs for part in pair)
    # Decode nested/encoded operation strings before policy evaluation.
    for component in components:
        decoded = component
        for _ in range(3):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        decoded = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", decoded)
        if RISKY_OPERATIONS.search(decoded.replace("_", " ").replace("-", " ")):
            raise ValueError("Potentially consequential navigation is blocked.")
    for key, value in pairs:
        if key.casefold() in RISKY_QUERY_KEYS and value.strip():
            raise ValueError("Potentially consequential navigation is blocked.")
    return url
