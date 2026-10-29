"""In-memory privacy audit log. Never store raw secret values."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class AuditEvent:
    timestamp: str
    action: str
    allowed: bool
    reason: str


class PrivacyAuditLog:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(
        self,
        action: str,
        allowed: bool,
        reason: str = "",
        **kwargs: Any,
    ) -> AuditEvent:
        """Record a decision without storing payloads or secret values."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=str(action),
            allowed=bool(allowed),
            reason=str(reason),
        )
        self._events.append(event)
        return event

    def log(self, action: str, allowed: bool, reason: str = "") -> AuditEvent:
        """Alias for record()."""
        return self.record(action, allowed, reason)

    def events(self) -> list[dict[str, Any]]:
        return [asdict(event) for event in self._events]

    def get_events(self) -> list[dict[str, Any]]:
        return self.events()

    def clear(self) -> None:
        self._events.clear()
