"""Validated, secret-free runtime settings for the PrivacyLens CLI."""

from dataclasses import dataclass
import os
from typing import Mapping


class ConfigurationError(ValueError):
    """Raised when non-secret runtime configuration is invalid."""


def _positive_int(name: str, raw: str | None, default: int, maximum: int) -> int:
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ConfigurationError(f"{name} must be a positive integer.") from None
    if value < 1 or value > maximum:
        raise ConfigurationError(f"{name} must be between 1 and {maximum}.")
    return value


@dataclass(frozen=True)
class Settings:
    max_actions: int = 5
    action_timeout_ms: int = 5000

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        return cls(
            max_actions=_positive_int(
                "PRIVACYLENS_MAX_ACTIONS", env.get("PRIVACYLENS_MAX_ACTIONS"), 5, 10
            ),
            action_timeout_ms=_positive_int(
                "PRIVACYLENS_ACTION_TIMEOUT_MS",
                env.get("PRIVACYLENS_ACTION_TIMEOUT_MS"), 5000, 30000,
            ),
        )
