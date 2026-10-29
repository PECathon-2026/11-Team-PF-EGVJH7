"""Bounded PrivacyLens browser workflow and command-line entry point."""

import argparse
import json
import os
from typing import Any

from playwright.sync_api import Error as PlaywrightError, sync_playwright

from contracts.models import Action
from core.agent.llm import build_request, call_llm
from core.agent.validator import validate
from core.browser.executor import (
    ExecutionError,
    _validate_navigation_url,
    execute_action,
)
from core.browser.snapshot import take_snapshot
from core.config import ConfigurationError, Settings
from core.detect import detect
from core.guard.canary import sensitive_canaries, sanitize_task_credentials
from core.guard.egress import EgressBlocked, assert_no_sensitive_values
from core.sanitize import sanitize


def _result(
    status: str,
    *,
    stage: str,
    message: str,
    actions=None,
    detections: int = 0,
    redaction_status: str = "unknown",
) -> dict[str, Any]:
    return {
        "ok": status == "completed",
        "status": status,
        "stage": stage,
        "message": message,
        "actions": actions or [],
        "detection_count": detections,
        "redaction_status": redaction_status,
    }


def _coerce_action(candidate: Any) -> Action:
    if isinstance(candidate, Action):
        return candidate

    if not isinstance(candidate, dict):
        raise ValueError("Action response must be an Action or object.")

    allowed = {
        "type",
        "element_id",
        "text",
        "secret_ref",
        "url",
        "reason",
    }

    if set(candidate) - allowed:
        raise ValueError("Action response contains unsupported fields.")

    return Action.model_validate(candidate)


def run_workflow(
    page,
    task: str,
    *,
    mode: str = "mock",
    max_actions: int = 5,
    timeout_ms: int = 5000,
    rules_path: str | None = None,
) -> dict[str, Any]:
    """Run the safe snapshot -> detect -> sanitize -> agent -> execute loop.

    The caller owns the browser and must navigate the page before calling this
    function. The workflow never returns raw detections or browser exception text.
    """

    if mode != "mock":
        return _result(
            "error",
            stage="configuration",
            message="Real LLM mode is not implemented; mock mode is available.",
        )

    if not isinstance(task, str) or not task.strip():
        return _result(
            "error",
            stage="configuration",
            message="A non-empty task is required.",
        )

    if type(max_actions) is not int or not 1 <= max_actions <= 10:
        return _result(
            "error",
            stage="configuration",
            message="max_actions must be between 1 and 10.",
        )

    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30000:
        return _result(
            "error",
            stage="configuration",
            message="timeout_ms must be between 1 and 30000.",
        )

    history = []
    detection_count = 0
    actions = []
    redaction_status = "unknown"

    for _ in range(max_actions):
        # 1. Capture the current page state.
        try:
            snapshot = take_snapshot(page, timeout_ms=timeout_ms)
        except Exception:
            return _result(
                "error",
                stage="snapshot",
                message="Page snapshot failed.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        # 2. Detect potentially sensitive data.
        try:
            detections = detect(snapshot)
            detection_count = len(detections)
        except Exception:
            return _result(
                "error",
                stage="detection",
                message="Sensitive-data detection failed.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        # 3. Sanitize text and screenshot.
        try:
            view = sanitize(
                snapshot,
                detections,
                rules_path=rules_path,
            )
        except Exception:
            return _result(
                "error",
                stage="sanitization",
                message="Sanitization failed; agent was not called.",
                actions=actions,
                detections=detection_count,
                redaction_status="failed",
            )

        # 4. Require complete image redaction before agent invocation.
        summary = next(
            (
                row
                for row in view.report
                if isinstance(row, dict)
                and row.get("kind") == "image_redaction_summary"
            ),
            None,
        )

        if summary is None or summary.get("status") != "complete":
            redaction_status = "incomplete"

            return _result(
                "blocked",
                stage="sanitization",
                message="Image redaction is unresolved; agent was not called.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        redaction_status = "complete"

        # 5. Build a sanitized request and check it before agent invocation.
        try:
            safe_task, task_values = sanitize_task_credentials(task)

            request = build_request(
                view,
                safe_task,
                history,
                secret_names=[],
            )

            canaries = (
                sensitive_canaries(snapshot, detections)
                + task_values
            )

            assert_no_sensitive_values(request, canaries)

        except EgressBlocked:
            return _result(
                "blocked",
                stage="egress",
                message=(
                    "Sensitive content remained in agent context; "
                    "transmission blocked."
                ),
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        except Exception:
            return _result(
                "error",
                stage="egress",
                message="Safe agent context could not be built.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        # 6. Obtain the next action.
        try:
            action = _coerce_action(call_llm(request))
        except Exception:
            return _result(
                "error",
                stage="agent",
                message="Agent returned an invalid action.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        # 7. Validate before execution.
        validation = validate(action, view)

        if not validation.ok:
            return _result(
                "blocked",
                stage="validation",
                message="Proposed action failed policy validation.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        # 8. Finish if the agent reports completion.
        if action.type == "done":
            return _result(
                "completed",
                stage="complete",
                message="Mock workflow reached its safe termination condition.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        # 9. Execute only after successful validation.
        try:
            execute_action(
                page,
                snapshot,
                action,
                timeout_ms=timeout_ms,
            )

        except ExecutionError:
            return _result(
                "blocked",
                stage="execution",
                message=(
                    "Browser executor blocked or could not "
                    "complete the action."
                ),
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        except PlaywrightError:
            return _result(
                "error",
                stage="execution",
                message="Browser action failed.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        except Exception:
            return _result(
                "error",
                stage="execution",
                message="Browser action failed.",
                actions=actions,
                detections=detection_count,
                redaction_status=redaction_status,
            )

        # Audit non-sensitive metadata only.
        # Never retain model-provided reason/text in history.
        action_record = {
            "type": action.type,
            "element_id": action.element_id,
            "ok": True,
        }

        actions.append(action_record.copy())
        history.append(action_record.copy())

    return _result(
        "action_limit",
        stage="execution",
        message="Maximum action count reached before task completion.",
        actions=actions,
        detections=detection_count,
        redaction_status=redaction_status,
    )


def run_task(page, task, vault=None, max_steps=None):
    """Compatibility entry point for the older run_task API.

    This adapter uses the current local workflow so the security checks remain
    centralized. Vault-backed secret restoration and interactive approval are
    not implemented by this adapter.

    The caller owns the Playwright page and browser lifecycle.
    """

    try:
        settings = Settings.from_env()

        step_limit = (
            settings.max_actions
            if max_steps is None
            else max_steps
        )

        timeout_ms = settings.action_timeout_ms

    except Exception:
        return {
            "ok": False,
            "reason": "Runtime configuration is invalid.",
            "history": [],
        }

    if type(step_limit) is not int or not 1 <= step_limit <= 10:
        return {
            "ok": False,
            "reason": "Invalid step limit.",
            "history": [],
        }

    # Fail closed if the supplied vault contains secrets that this workflow
    # cannot safely restore and use.
    if vault is not None:
        try:
            secret_names = vault.names()
        except Exception:
            return {
                "ok": False,
                "reason": "Vault access failed; task was not executed.",
                "history": [],
            }

        if secret_names:
            return {
                "ok": False,
                "reason": (
                    "Vault-backed secret use is not implemented "
                    "in this workflow."
                ),
                "history": [],
            }

    # Delegate to the existing sanitized, bounded workflow.
    result = run_workflow(
        page,
        task,
        mode="mock",
        max_actions=step_limit,
        timeout_ms=timeout_ms,
    )

    # Preserve the legacy result keys while also exposing safe status metadata.
    return {
        "ok": result.get("ok", False),
        "reason": result.get("message", "Task did not complete."),
        "history": result.get("actions", []),
        "status": result.get("status", "error"),
        "stage": result.get("stage", "unknown"),
        "detection_count": result.get("detection_count", 0),
        "redaction_status": result.get("redaction_status", "unknown"),
    }


def run_orchestrator(
    mock_llm: bool = False,
    *,
    url: str | None = None,
    task: str = "Review the page safely",
    settings: Settings | None = None,
) -> int:
    """Launch Chromium, run the mock workflow, and emit a safe JSON result."""

    if not mock_llm:
        print(
            json.dumps(
                _result(
                    "error",
                    stage="configuration",
                    message=(
                        "Real LLM mode is not implemented; "
                        "use --mock-llm."
                    ),
                )
            )
        )
        return 2

    try:
        settings = settings or Settings.from_env()

        start_url = _validate_navigation_url(
            url
            or os.environ.get(
                "PRIVACYLENS_START_URL",
                "http://127.0.0.1:8000/checkout.html",
            )
        )

    except (ConfigurationError, ExecutionError):
        print(
            json.dumps(
                _result(
                    "error",
                    stage="configuration",
                    message="Invalid runtime configuration or start URL.",
                )
            )
        )
        return 2

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)

            try:
                page = browser.new_page(
                    viewport={
                        "width": 1280,
                        "height": 800,
                    }
                )

                page.set_default_timeout(settings.action_timeout_ms)

                try:
                    page.goto(
                        start_url,
                        wait_until="domcontentloaded",
                        timeout=settings.action_timeout_ms,
                    )

                except PlaywrightError:
                    result = _result(
                        "error",
                        stage="navigation",
                        message="Could not open the configured start page.",
                    )

                else:
                    result = run_workflow(
                        page,
                        task,
                        mode="mock",
                        max_actions=settings.max_actions,
                        timeout_ms=settings.action_timeout_ms,
                    )

            finally:
                browser.close()

    except PlaywrightError:
        result = _result(
            "error",
            stage="browser",
            message="Chromium could not be started.",
        )

    print(json.dumps(result, ensure_ascii=False))

    return 0 if result["ok"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PrivacyLens privacy-safe browser workflow"
    )

    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Run without external LLM credentials",
    )

    parser.add_argument(
        "--url",
        help="HTTP(S) start URL (or PRIVACYLENS_START_URL)",
    )

    parser.add_argument(
        "--task",
        default="Review the page safely",
        help="Task supplied to the mock agent",
    )

    parser.add_argument(
        "--max-actions",
        type=int,
        help=(
            "Limit non-terminal browser actions "
            "(default from environment)"
        ),
    )

    parser.add_argument(
        "--timeout-ms",
        type=int,
        help="Per-action timeout (default from environment)",
    )

    args = parser.parse_args()

    try:
        defaults = Settings.from_env()

        settings = Settings(
            max_actions=(
                defaults.max_actions
                if args.max_actions is None
                else args.max_actions
            ),
            action_timeout_ms=(
                defaults.action_timeout_ms
                if args.timeout_ms is None
                else args.timeout_ms
            ),
        )

        # Validate command-line overrides against safe bounds.
        if not 1 <= settings.max_actions <= 10:
            raise ConfigurationError(
                "CLI action limit exceeds safe bounds."
            )

        if not 1 <= settings.action_timeout_ms <= 30000:
            raise ConfigurationError(
                "CLI timeout exceeds safe bounds."
            )

    except ConfigurationError:
        print(
            json.dumps(
                _result(
                    "error",
                    stage="configuration",
                    message=(
                        "Invalid action limit or timeout configuration."
                    ),
                )
            )
        )
        return 2

    return run_orchestrator(
        args.mock_llm,
        url=args.url,
        task=args.task,
        settings=settings,
    )


if __name__ == "__main__":
    raise SystemExit(main())