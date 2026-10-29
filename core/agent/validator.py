
from core.config import load_config
from core.agent.approval import needs_approval

from pathlib import Path
from urllib.parse import urlsplit

import yaml

from contracts.models import Action, SanitizedView, ValidationResult


ROOT = Path(__file__).resolve().parents[2]


def _load_allowed_domains():
    """Read the domain allowlist from config.yaml."""
    config_path = ROOT / "config.yaml"

    try:
        with config_path.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file) or {}
    except (OSError, yaml.YAMLError):
        return []

    domains = config.get("allowed_domains", [])
    if not isinstance(domains, list):
        return []

    return [
        str(domain).strip().lower().rstrip(".")
        for domain in domains
        if isinstance(domain, str) and domain.strip()
    ]


def _domain_allowed(url, allowed_domains):
    """Allow only HTTP(S) URLs on an explicitly allowed domain."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        # Accessing port also detects malformed port numbers.
        _ = parsed.port
    except (TypeError, ValueError):
        return False

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False

    hostname = hostname.lower().rstrip(".")

    for domain in allowed_domains:
        domain = domain.lower().rstrip(".")
        if hostname == domain or hostname.endswith("." + domain):
            return True

    return False


def _element_compatible(action, element):
    """Check whether an action is suitable for its target element."""
    tag = (element.tag or "").lower()
    role = (element.role or "").lower()
    input_type = (element.type or "text").lower()
    attrs = element.attrs or {}

    if action.type == "click":
        return (
            tag in {"button", "a"}
            or role in {"button", "link", "checkbox", "radio", "tab"}
            or (
                tag == "input"
                and input_type in {
                    "button", "submit", "reset", "checkbox", "radio"
                }
            )
        )

    if action.type == "type":
        return (
            (
                tag == "input"
                and input_type not in {
                    "button", "submit", "reset", "checkbox",
                    "radio", "file", "hidden", "image"
                }
            )
            or tag == "textarea"
            or str(attrs.get("contenteditable", "")).lower() == "true"
        )

    if action.type == "select":
        return tag == "select"

    if action.type == "scroll":
        return True

    return False


def validate(
    action: Action,
    view: SanitizedView,
    allowed_domains=None,
    vault_names=None,
) -> ValidationResult:
    """
    Validate an agent action against the sanitized page, domain
    allowlist, element type, and permitted vault references.

    Pass vault_names as the collection of reference names available
    in the local vault. Secret values must never be passed here.
    """
    reasons = []

    if allowed_domains is None:
        allowed_domains = load_config()["allowed_domains"]

    if not allowed_domains:
        return ValidationResult(
            ok=False,
            reasons=["Domain allowlist is missing or invalid."],
        )

    if not _domain_allowed(view.url, allowed_domains):
        return ValidationResult(
            ok=False,
            reasons=["Current page domain is not allowlisted."],
        )

    if action.type == "done":
        return ValidationResult(ok=True)

    if action.type == "navigate":
        if not action.url:
            return ValidationResult(
                ok=False,
                reasons=["Navigate action is missing a URL."],
            )

        if not _domain_allowed(action.url, allowed_domains):
            return ValidationResult(
                ok=False,
                reasons=["Navigation target domain is not allowlisted."],
            )

        return ValidationResult(ok=True)

    if action.type not in {"click", "type", "select", "scroll"}:
        return ValidationResult(
            ok=False,
            reasons=["Unsupported action type."],
        )

    if not action.element_id:
        return ValidationResult(
            ok=False,
            reasons=["Action is missing an element ID."],
        )

    element = next(
        (item for item in view.elements if item.id == action.element_id),
        None,
    )

    if element is None:
        return ValidationResult(
            ok=False,
            reasons=[
                f"Element ID '{action.element_id}' does not exist "
                "in the sanitized view."
            ],
        )

    if not _element_compatible(action, element):
        return ValidationResult(
            ok=False,
            reasons=[
                f"Action '{action.type}' is incompatible with "
                f"element '{element.id}' ({element.tag})."
            ],
        )

    if action.type == "type":
        if action.secret_ref:
            if vault_names is None:
                return ValidationResult(
                    ok=False,
                    reasons=[
                        "Vault references cannot be verified: "
                        "vault names were not provided."
                    ],
                )

            if action.secret_ref not in vault_names:
                return ValidationResult(
                    ok=False,
                    reasons=[
                        f"Secret reference '{action.secret_ref}' "
                        "does not exist in the vault."
                    ],
                )
        elif action.text is None:
            return ValidationResult(
                ok=False,
                reasons=[
                    "Type action requires text or a secret reference."
                ],
            )

    if action.type == "select" and action.text is None:
        return ValidationResult(
            ok=False,
            reasons=["Select action requires an option value."],
        )

    return ValidationResult(
        ok=True,
        needs_approval=needs_approval(action, element),
        reasons=reasons,
    )
