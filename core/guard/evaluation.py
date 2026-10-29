"""Deterministic canary-based privacy firewall evaluation."""

from dataclasses import dataclass, asdict
from typing import Any, Iterable

from core.guard.canary import detect_canary_leak


@dataclass(frozen=True)
class FirewallMetrics:
    injected: int
    detected: int
    blocked: int
    missed: int
    false_positives: int

    def as_dict(self):
        return asdict(self)


def evaluate_canary_firewall(
    cases: Iterable[dict[str, Any]],
) -> FirewallMetrics:
    """Evaluate canary detection against explicitly labelled cases."""
    injected = 0
    detected = 0
    blocked = 0
    missed = 0
    false_positives = 0

    for case in cases:
        expected_leak = bool(case.get("expected_leak", False))

        if expected_leak:
            injected += 1

        result = detect_canary_leak(
            case.get("payload"),
            case.get("canaries", []),
        )

        rejected = not result.ok

        if expected_leak and rejected:
            detected += 1
            blocked += 1

        elif expected_leak and not rejected:
            missed += 1

        elif not expected_leak and rejected:
            false_positives += 1

    return FirewallMetrics(
        injected=injected,
        detected=detected,
        blocked=blocked,
        missed=missed,
        false_positives=false_positives,
    )