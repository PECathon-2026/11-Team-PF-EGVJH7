
from core.agent.approval import request_approval
from core.agent.llm import build_request, call_llm
from core.agent.validator import validate
from core.browser.executor import execute_action
from core.browser.snapshot import take_snapshot
from core.browser.vault import SecretVault
from core.config import load_config
from core.detect import detect
from core.guard.egress import check_egress
from core.sanitize import sanitize


def run_task(page, task, vault=None, max_steps=None):
    """
    Run the PrivacyLens decision loop on an existing Playwright page.

    The caller owns the browser and page lifecycle.
    Secret values stay in the local vault.
    """

    vault = vault if vault is not None else SecretVault()
    config = load_config()
    step_limit = max_steps if max_steps is not None else config["max_steps"]

    if not isinstance(step_limit, int) or isinstance(step_limit, bool) or step_limit < 1:
        return {"ok": False, "reason": "Invalid step limit.", "history": []}

    history = []

    for step in range(step_limit):
        # 1. Capture the current page state.
        try:
            snapshot = take_snapshot(page)

            # 2. Detect sensitive data and sanitize text and screenshot.
            detections = detect(snapshot)
            view = sanitize(snapshot, detections)
        except Exception:
            return {
                "ok": False,
                "reason": "Snapshot or sanitization failed; cloud request blocked.",
                "history": history,
            }

        # 3. Build a request from the sanitized view only.
        try:
            request = build_request(
                view=view,
                task=task,
                history=history,
                secret_names=sorted(vault.names()),
            )
        except Exception:
            return {
                "ok": False,
                "reason": "Could not build a safe AI request.",
                "history": history,
            }

        # 4. Check outgoing text and structured page data before cloud use.
        # The screenshot is separately sanitized by core.sanitize.
        egress_payload = {
            key: value
            for key, value in request.items()
            if key != "screenshot_b64"
        }

        guard = check_egress(egress_payload)
        if not guard.ok:
            return {
                "ok": False,
                "reason": "Egress guard blocked the AI request.",
                "details": guard.reasons,
                "history": history,
            }

        # 5. Ask Gemini for one structured Action.
        try:
            action = call_llm(request)
        except Exception:
            return {
                "ok": False,
                "reason": "AI request failed or returned an invalid action.",
                "history": history,
            }

        # 6. Validate the action against the current sanitized view.
        try:
            result = validate(
                action=action,
                view=view,
                allowed_domains=config["allowed_domains"],
                vault_names=vault.names(),
            )
        except Exception:
            return {
                "ok": False,
                "reason": "Action validation failed; execution blocked.",
                "history": history,
            }

        if not result.ok:
            return {
                "ok": False,
                "reason": "Action rejected by Validator v2.",
                "details": result.reasons,
                "history": history,
            }

        # 7. Stop if Gemini reports that the task is complete.
        if action.type == "done":
            return {
                "ok": True,
                "reason": action.reason or "Task completed.",
                "history": history,
            }

        # 8. Require explicit terminal approval when validation demands it.
        if result.needs_approval:
            try:
                approved = request_approval(action)
            except Exception:
                approved = False

            if not approved:
                return {
                    "ok": False,
                    "reason": "User denied or could not provide approval.",
                    "history": history,
                }

        # 9. Execute only after validation and any required approval.
        outcome = execute_action(
            page=page,
            action=action,
            vault=vault,
        )

        # Do not store action.text or any resolved secret in history.
        history.append({
            "step": step + 1,
            "action_type": action.type,
            "element_id": action.element_id,
            "reason": action.reason,
            "success": outcome.get("ok", False),
            "result": outcome.get("message", outcome.get("error", "")),
        })

        if not outcome.get("ok", False):
            return {
                "ok": False,
                "reason": "Browser action failed.",
                "history": history,
            }

    return {
        "ok": False,
        "reason": "Maximum step limit reached.",
        "history": history,
    }
