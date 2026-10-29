"""Fail-closed privacy firewall for outgoing payloads."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Iterable


@dataclass
class GuardResult:
    """Result returned by privacy guard validation."""

    ok: bool
    reasons: list[str] = field(default_factory=list)
    leaks: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok

    @property
    def allowed(self) -> bool:
        """Compatibility with code using the older result interface."""
        return self.ok


# Backward-compatible name.
EgressResult = GuardResult


def extract_strings(value: Any) -> list[str]:
    """Extract strings recursively; reject uninspectable values."""

    if isinstance(value, str):
        return [value]

    if isinstance(value, Mapping):
        result = []
        for key, item in value.items():
            result.extend(extract_strings(key))
            result.extend(extract_strings(item))
        return result

    if isinstance(value, (list, tuple, set, frozenset)):
        result = []
        for item in value:
            result.extend(extract_strings(item))
        return result

    if is_dataclass(value) and not isinstance(value, type):
        return extract_strings(asdict(value))

    if hasattr(value, "model_dump") and callable(value.model_dump):
        return extract_strings(value.model_dump(mode="json"))

    if hasattr(value, "__dict__"):
        result = []
        for attr_name, attr_value in vars(value).items():
            if attr_name.startswith("_"):
                continue
            result.extend(extract_strings(attr_value))
        return result

    if value is None or isinstance(value, (bool, int, float)):
        return []

    raise ValueError(
        f"Unsupported payload value type: {type(value).__name__}"
    )


# Backward-compatible helper.
_extract_strings = extract_strings


def _collect_inventory(values: Iterable[str]) -> list[str]:
    """Validate the inventory of protected values."""

    if values is None:
        raise ValueError("Inventory cannot be None.")

    try:
        inventory = list(values)
    except Exception as exc:
        raise ValueError("Inventory could not be inspected.") from exc

    if not inventory:
        raise ValueError("Inventory is empty.")

    if any(not isinstance(value, str) or not value for value in inventory):
        raise ValueError("Inventory contains invalid entries.")

    return inventory


def _inspect_payload(payload: Any) -> list[str]:
    """Inspect the complete payload or reject it."""

    try:
        return extract_strings(payload)
    except Exception as exc:
        raise ValueError(f"Payload could not be inspected: {exc}") from exc


def _find_leaks(
    strings: list[str],
    protected_values: list[str],
) -> list[str]:
    """Return protected values found anywhere in outgoing strings."""

    return sorted({
        protected
        for protected in protected_values
        if any(protected in text for text in strings)
    })


def validate_no_leakage(
    payload: Any,
    secrets: Iterable[str] = (),
) -> GuardResult:
    """Reject leaks and fail closed for empty inventories or invalid data."""

    try:
        secret_values = _collect_inventory(secrets)
        strings = _inspect_payload(payload)
        leaks = _find_leaks(strings, secret_values)

        if leaks:
            return GuardResult(
                ok=False,
                reasons=["Protected original value detected."],
                leaks=leaks,
            )

        return GuardResult(ok=True)

    except Exception as exc:
        return GuardResult(
            ok=False,
            reasons=[str(exc)],
        )


def validate_payload(
    payload: Any,
    secrets: Iterable[str] = (),
    canaries: Iterable[str] = (),
) -> GuardResult:
    """Check outgoing data for protected values and canaries."""

    try:
        if secrets is None or canaries is None:
            raise ValueError("Secret and canary inventories cannot be None.")

        secret_values = list(secrets)
        canary_values = list(canaries)

        # Empty inventories are valid when there are no secrets or canaries.
        # Still reject invalid entries whenever an inventory is provided.
        combined = secret_values + canary_values
        if any(not isinstance(value, str) or not value for value in combined):
            raise ValueError("Inventory contains invalid entries.")
        protected_values = combined

        strings = _inspect_payload(payload)
        leaks = _find_leaks(strings, protected_values)

        if leaks:
            return GuardResult(
                ok=False,
                reasons=["Privacy firewall blocked outgoing payload."],
                leaks=leaks,
            )

        return GuardResult(ok=True)

    except Exception as exc:
        return GuardResult(
            ok=False,
            reasons=[str(exc)],
        )


def validate_outgoing(
    payload: Any,
    secrets: Iterable[str] = (),
    canaries: Iterable[str] = (),
) -> GuardResult:
    """Final fail-closed validation before data leaves the application."""

    return validate_payload(
        payload=payload,
        secrets=secrets,
        canaries=canaries,
    )
"""Fail-closed guard for context sent to an agent."""

from collections.abc import Mapping, Sequence


class EgressBlocked(RuntimeError):
    """Raised without including any sensitive source content."""


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for nested in value.values():
            yield from _strings(nested)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        for nested in value:
            yield from _strings(nested)


def assert_no_sensitive_values(payload, canaries: list[str]) -> None:
    outgoing = tuple(_strings(payload))
    if any(secret in text for secret in canaries for text in outgoing):
        raise EgressBlocked(
            "Agent context contains detected sensitive content; transmission blocked."
        )
