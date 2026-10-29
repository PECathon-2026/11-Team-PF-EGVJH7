"""Evaluation metrics for the synthetic-canary privacy firewall."""

from dataclasses import dataclass
from typing import Iterable

from core.guard.canary import detect_canary_leak


@dataclass
class FirewallMetrics:
    total: int
    detected: int
    missed: int
    detection_rate: float
    injected: int = 0
    blocked: int = 0
    false_positives: int = 0

    def as_dict(self) -> dict:
        return {
            "injected": self.injected,
            "detected": self.detected,
            "blocked": self.blocked,
            "missed": self.missed,
            "false_positives": self.false_positives,
        }


def evaluate_canary_firewall(
    payloads: Iterable[object],
    canaries: Iterable[str] | None = None,
) -> FirewallMetrics:
    """Evaluate canary detection using cases or shared canaries."""
    cases = list(payloads)

    if not cases:
        return FirewallMetrics(
            total=0,
            detected=0,
            missed=0,
            detection_rate=0.0,
        )

    # Legacy API: evaluate payloads against a shared canary inventory.
    if canaries is not None:
        canary_values = [
            value for value in canaries
            if isinstance(value, str) and value
        ]

        detected = 0
        for payload in cases:
            try:
                result = detect_canary_leak(payload, canary_values)
                if not result.ok:
                    detected += 1
            except Exception:
                continue

        total = len(cases)
        return FirewallMetrics(
            total=total,
            detected=detected,
            missed=total - detected,
            detection_rate=detected / total,
            injected=total,
            blocked=detected,
        )

    # Case-based API: each case supplies its own canaries and expected result.
    injected = 0
    detected = 0
    blocked = 0
    missed = 0
    false_positives = 0

    for case in cases:
        if not isinstance(case, dict):
            missed += 1
            continue

        payload = case.get("payload")
        case_canaries = case.get("canaries", [])
        expected_leak = bool(case.get("expected_leak", False))

        if not isinstance(case_canaries, (list, tuple, set)):
            case_canaries = []

        case_canaries = [
            value for value in case_canaries
            if isinstance(value, str) and value
        ]

        if expected_leak:
            injected += 1

        try:
            result = detect_canary_leak(payload, case_canaries)
            actual_leak = not result.ok
        except Exception:
            actual_leak = False

        if expected_leak:
            if actual_leak:
                detected += 1
                blocked += 1
            else:
                missed += 1
        elif actual_leak:
            false_positives += 1

    total = len(cases)

    return FirewallMetrics(
        total=total,
        detected=detected,
        missed=missed,
        detection_rate=detected / injected if injected else 0.0,
        injected=injected,
        blocked=blocked,
        false_positives=false_positives,
    )