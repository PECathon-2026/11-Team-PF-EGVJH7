
from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError

from contracts.models import Action
from core.browser.vault import SecretVault


def execute_action(
    page: Page,
    action: Action,
    vault: SecretVault,
    timeout_ms: int = 5000,
) -> dict:
    """
    Execute a previously validated action in the browser.

    Validation and approval must happen before this function is called.
    Secret values are resolved locally and are never logged.
    """

    if action.type == "done":
        return {"ok": True, "message": "Task completed."}

    if action.type == "navigate":
        if not action.url:
            return {"ok": False, "error": "Missing navigation URL."}

        try:
            page.goto(
                action.url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
            return {"ok": True, "message": "Navigation completed."}
        except PlaywrightTimeoutError:
            return {
                "ok": False,
                "error": "Navigation timed out.",
            }
        except Exception:
            return {
                "ok": False,
                "error": "Navigation failed.",
            }

    if not action.element_id:
        return {"ok": False, "error": "Missing element ID."}

    # Element IDs are assigned by take_snapshot().
    # Escape quotes so the ID cannot alter the selector.
    element_id = action.element_id.replace("\\", "\\\\").replace('"', '\\"')
    locator = page.locator(f'[data-pl-id="{element_id}"]')

    try:
        if locator.count() != 1:
            return {
                "ok": False,
                "error": "Target element is missing or ambiguous.",
            }

        locator = locator.first
        locator.wait_for(state="visible", timeout=timeout_ms)

        if action.type == "click":
            locator.click(timeout=timeout_ms)

        elif action.type == "type":
            if action.secret_ref:
                if not vault.has(action.secret_ref):
                    return {
                        "ok": False,
                        "error": "Secret reference is not available.",
                    }

                # Resolve the secret locally. Never log or return its value.
                value = vault.get(action.secret_ref)
            elif action.text is not None:
                value = action.text
            else:
                return {
                    "ok": False,
                    "error": "Type action has no text or secret reference.",
                }

            locator.fill(value, timeout=timeout_ms)

        elif action.type == "select":
            if action.text is None:
                return {
                    "ok": False,
                    "error": "Select action is missing its option value.",
                }

            locator.select_option(
                value=action.text,
                timeout=timeout_ms,
            )

        elif action.type == "scroll":
            locator.scroll_into_view_if_needed(timeout=timeout_ms)
            page.mouse.wheel(0, 500)

        else:
            return {
                "ok": False,
                "error": "Unsupported action type.",
            }

        return {
            "ok": True,
            "message": f"{action.type.capitalize()} action completed.",
        }

    except PlaywrightTimeoutError:
        return {
            "ok": False,
            "error": "Browser action timed out.",
        }
    except Exception:
        # Avoid returning page content, input values, or secret values.
        return {
            "ok": False,
            "error": "Browser action failed.",
        }
