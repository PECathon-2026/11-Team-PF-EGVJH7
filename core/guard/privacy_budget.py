"""Rule-based privacy disclosure decisions."""

from dataclasses import dataclass


@dataclass
class DisclosureDecision:
    allowed: bool
    risk: str
    reason: str
    representation: str = ""

    @property
    def disclose(self) -> bool:
        """Whether disclosure is permitted."""
        return self.allowed


def decide_disclosure(
    sensitivity: str = "medium",
    purpose: str = "general",
    consent: bool = False,
    **kwargs,
) -> DisclosureDecision:
    """Make conservative, rule-based disclosure decisions."""

    level = str(sensitivity).strip().lower()
    purpose_value = str(purpose).strip().lower()

    # Credentials and secrets must never be disclosed.
    never_disclose = {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "credit_card",
        "cvv",
        "ssn",
    }

    if level in never_disclose or level in {
        "critical",
        "highly_sensitive",
    }:
        return DisclosureDecision(
            False,
            "high",
            "Highly sensitive data must not be disclosed.",
            "[PROTECTED]",
        )

    # Other sensitive personal data requires explicit consent.
    if level in {
        "high",
        "personal",
        "sensitive",
    } and not consent:
        return DisclosureDecision(
            False,
            "high",
            "Sensitive data requires explicit consent.",
            "[PROTECTED]",
        )

    if purpose_value in {
        "unknown",
        "unspecified",
        "unnecessary",
        "",
    }:
        return DisclosureDecision(
            False,
            "medium",
            "Disclosure purpose is unclear.",
            "[PROTECTED]",
        )

    # Only disclose a boolean status for field-population checks.
    if "field_populated" in kwargs:
        representation = (
            f"populated={bool(kwargs['field_populated'])}"
        )
    else:
        representation = "allowed=True"

    risk = (
        level
        if level in {"low", "medium", "high"}
        else "medium"
    )

    return DisclosureDecision(
        True,
        risk,
        "Allowed by the configured rule-based policy.",
        representation,
    )

