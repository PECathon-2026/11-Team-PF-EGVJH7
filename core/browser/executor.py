from typing import Optional
from urllib.parse import urlparse, urljoin

from playwright.sync_api import (
    Error as PlaywrightError,
    Page,
    TimeoutError as PlaywrightTimeoutError,
)

from contracts.models import Action, PageSnapshot
from core.browser.navigation import validate_navigation_url


class ExecutionError(Exception):
    """Raised when a browser action cannot be executed safely."""


# Restrict navigation to ordinary web URLs.
ALLOWED_SCHEMES = {"http", "https"}

# These actions can trigger consequential operations.
# The executor rejects them by default until the project integrates
# an explicit approval mechanism.
SENSITIVE_BUTTON_WORDS = {
    "pay",
    "purchase",
    "buy",
    "checkout",
    "transfer",
    "delete",
    "remove account",
    "submit order",
    "confirm payment",
}


def _validate_navigation_url(url: Optional[str]) -> str:
    """Validate a navigation URL before opening it."""
    try:
        return validate_navigation_url(url)
    except ValueError as exc:
        raise ExecutionError(str(exc)) from None


def _get_element(page: Page, snapshot: PageSnapshot, element_id: str):
    snapshot_ids = {element.id for element in snapshot.elements}

    if element_id not in snapshot_ids:
        raise ExecutionError(
            f"Element ID '{element_id}' is not in the supplied snapshot."
        )

    locator = page.locator(f'[data-pl-id="{element_id}"]')

    if locator.count() != 1:
        raise ExecutionError(
            f"Element ID '{element_id}' is missing or ambiguous."
        )

    if snapshot.snapshot_id and locator.get_attribute("data-pl-snapshot") != snapshot.snapshot_id:
        raise ExecutionError("Snapshot is stale; take a fresh snapshot before acting.")

    expected = next(item for item in snapshot.elements if item.id == element_id)
    current = locator.evaluate("""el => ({
        tag: el.tagName.toLowerCase(), type: el.getAttribute('type'),
        name: el.getAttribute('name'), value: el.value || '',
        text: el.matches('input, textarea, select') ? '' :
            (el.innerText || el.textContent || '').trim(),
        placeholder: el.getAttribute('placeholder') || '',
        href: el.getAttribute('href') || '', disabled: Boolean(el.disabled),
        readonly: Boolean(el.readOnly)
    })""")
    attrs = expected.attrs or {}
    if any((current[key] != value) for key, value in {
        "tag": expected.tag,
        "type": expected.type,
        "name": expected.name,
        "value": expected.value,
        "text": expected.text,
        "placeholder": expected.placeholder,
        "href": attrs.get("href", ""),
        "disabled": attrs.get("disabled", False),
        "readonly": attrs.get("readonly", False),
    }.items()):
        raise ExecutionError("Snapshot is stale; take a fresh snapshot before acting.")

    return locator


def _is_sensitive_target(element) -> bool:
    """Identify obvious high-impact buttons using their visible text."""

    description = " ".join(
        [
            element.text or "",
            element.label or "",
            element.name or "",
        ]
    ).lower()

    return any(word in description for word in SENSITIVE_BUTTON_WORDS)


def execute_action(
    page: Page,
    snapshot: PageSnapshot,
    action: Action,
    timeout_ms: int = 5000,
) -> dict:
    """
    Validate and execute a single structured browser action.

    The caller owns the browser lifecycle and is responsible for taking
    a fresh snapshot before each action.

    Returns a structured execution result.
    """

    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30000:
        raise ValueError("timeout_ms must be between 1 and 30000.")

    if action.type == "done":
        return {
            "ok": True,
            "action": "done",
            "message": "Task completed.",
        }

    if action.type == "navigate":
        url = _validate_navigation_url(action.url)

        try:
            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
        except PlaywrightTimeoutError:
            raise ExecutionError("Navigation timed out before the page became ready.") from None
        except PlaywrightError as exc:
            raise ExecutionError(f"Navigation failed: {exc}") from None

        return {
            "ok": True,
            "action": "navigate",
            "url": page.url,
        }

    if action.type == "scroll":
        # Scroll the page rather than an arbitrary element.
        try:
            page.evaluate("window.scrollBy(0, window.innerHeight * 0.8)")
        except PlaywrightTimeoutError:
            raise ExecutionError("Scroll action timed out.") from None
        except PlaywrightError:
            raise ExecutionError("Scroll action failed.") from None

        return {
            "ok": True,
            "action": "scroll",
            "url": page.url,
        }

    if not action.element_id:
        raise ExecutionError(
            "This action requires an element ID."
        )

    try:
        locator = _get_element(page, snapshot, action.element_id)
    except ExecutionError:
        raise
    except PlaywrightError:
        raise ExecutionError("Element lookup failed; take a fresh snapshot.") from None

    element = next(
        item
        for item in snapshot.elements
        if item.id == action.element_id
    )

    try:
        if action.type == "click":
            if _is_sensitive_target(element):
                raise ExecutionError(
                    "Potentially consequential button requires approval."
                )

            # Submit controls can trigger purchases or other consequential
            # form actions even when their labels do not contain risk keywords.
            control_type = (element.type or "").lower()
            is_form_submit = control_type in {"submit", "image"} or (
                element.tag == "button" and control_type in {"", "submit"}
            )
            if is_form_submit:
                raise ExecutionError("Form submission requires an explicit approval policy.")

            if element.tag != "a":
                raise ExecutionError(
                    "Script-backed control clicks are disabled until an explicit "
                    "approval policy is available."
                )

            href = locator.get_attribute("href")
            if not href:
                raise ExecutionError("Link has no navigable destination.")
            destination = _validate_navigation_url(urljoin(page.url, href))

            if not locator.is_visible() or not locator.is_enabled():
                raise ExecutionError("Cannot click a hidden or disabled element.")

            locator.click(timeout=timeout_ms)

            return {
                "ok": True,
                "action": "click",
                "element_id": action.element_id,
            }

        if action.type == "type":
            if action.text is None and action.secret_ref is None:
                raise ExecutionError(
                    "Type action requires text or an authorized secret reference."
                )

            if action.text is not None and action.secret_ref is not None:
                raise ExecutionError(
                    "Provide either text or secret_ref, not both."
                )

            if action.secret_ref is not None:
                # Secret restoration belongs to the vault integration.
                # Never interpret a secret reference as literal text.
                raise ExecutionError(
                    "Secret references are not supported until vault integration."
                )

            if element.tag not in {"input", "textarea"}:
                raise ExecutionError(
                    "Typing is restricted to input and textarea elements."
                )

            if element.type == "password":
                raise ExecutionError(
                    "Password input requires an explicit secure-input policy."
                )

            if element.type == "hidden" or not locator.is_visible() or not locator.is_enabled():
                raise ExecutionError("Cannot type into a hidden or disabled input.")
            if locator.get_attribute("readonly") is not None:
                raise ExecutionError("Cannot type into a read-only input.")

            locator.fill(
                action.text,
                timeout=timeout_ms,
            )

            return {
                "ok": True,
                "action": "type",
                "element_id": action.element_id,
            }

        if action.type == "select":
            if element.tag != "select":
                raise ExecutionError(
                    "Select action requires a select element."
                )

            if action.text is None:
                raise ExecutionError(
                    "Select action requires an option value."
                )

            if not locator.is_visible() or not locator.is_enabled():
                raise ExecutionError("Cannot select an option in a hidden or disabled control.")

            locator.select_option(
                value=action.text,
                timeout=timeout_ms,
            )

            return {
                "ok": True,
                "action": "select",
                "element_id": action.element_id,
            }

        raise ExecutionError(
            f"Unsupported action type: {action.type}"
        )

    except PlaywrightTimeoutError:
        raise ExecutionError(
            "Browser action timed out. Take a fresh snapshot and retry "
            "only after checking the current page state."
        ) from None
    except PlaywrightError:
        raise ExecutionError("Browser action failed or its target is unavailable.") from None
