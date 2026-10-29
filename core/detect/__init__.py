from contracts.models import PageSnapshot, Detection

def detect(snapshot: PageSnapshot) -> list[Detection]:
    """Full page detection. Stub — returns nothing yet."""
    return []

def scan_text(text: str) -> list[Detection]:
    """Regex-only text scan for P3's guard. Stub — returns nothing yet."""
    return []
