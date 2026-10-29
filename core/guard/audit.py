"""Secret-free audit events for the Privacy Time Machine."""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    event: str
    category: str
    technique: str
    decision: str
    reason: str
    transmitted: bool = False


class PrivacyAuditLog:
    """In-memory event log. Never pass raw values as event fields."""

    def __init__(self):
        self._events: list[AuditEvent] = []

    def record(
        self,
        event: str,
        category: str,
        technique: str,
        decision: str,
        reason: str,
        transmitted: bool = False,
    ) -> AuditEvent:
        safe = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event=str(event)[:80],
            category=str(category)[:40],
            technique=str(technique)[:80],
            decision=str(decision)[:40],
            reason=str(reason)[:240],
            transmitted=bool(transmitted),
        )

        self._events.append(safe)
        return safe

    def events(self) -> list[dict[str, Any]]:
        return [
            asdict(event)
            for event in self._events
        ]

    def summary(self) -> dict[str, int]:
        events = self._events

        return {
            "events": len(events),
            "detected": sum(
                event.event == "secret_detected"
                for event in events
            ),
            "blocked": sum(
                event.decision == "blocked"
                for event in events
            ),
            "transmitted": sum(
                event.transmitted
                for event in events
            ),
            "warnings": sum(
                event.decision == "warning"
                for event in events
            ),
        }