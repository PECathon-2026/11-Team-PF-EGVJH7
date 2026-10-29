import json

import pytest
from playwright.sync_api import sync_playwright

from contracts.models import Action
from core import orchestrator
from core.config import ConfigurationError, Settings
from core.guard.egress import EgressBlocked, assert_no_sensitive_values


def _page(content="<main><p>Ready</p></main>"):
    playwright = sync_playwright().start()
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 800, "height": 600})
    page.route("https://privacylens.test/**", lambda route: route.fulfill(
        status=200, content_type="text/html", body=content
    ))
    page.goto("https://privacylens.test/")
    return playwright, browser, page


def test_mock_workflow_sanitizes_before_agent_and_terminates(monkeypatch):
    secret = "case.test+tag@example.test"
    playwright, browser, page = _page(
        f'<label>Email <input value="{secret}"></label><p>Safe page</p>'
    )
    requests = []
    original_agent = orchestrator.call_llm

    def capture(request):
        requests.append(request)
        return original_agent(request)

    monkeypatch.setattr(orchestrator, "call_llm", capture)
    try:
        result = orchestrator.run_workflow(page, "Review this page", max_actions=3)
    finally:
        browser.close()
        playwright.stop()

    assert result["status"] == "completed"
    assert result["redaction_status"] == "complete"
    assert result["actions"] == [{"type": "scroll", "element_id": None, "ok": True}]
    assert len(requests) == 2
    assert requests[0]["task"] == "Review this page"
    assert secret not in json.dumps(requests)
    assert "attrs" not in requests[0]["elements"][0]


def test_unresolved_image_redaction_blocks_agent(monkeypatch):
    playwright, browser, page = _page(
        '<input aria-label="Email" value="case.test@example.test" '
        'style="position:absolute;left:-12000px">'
    )
    calls = []
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: calls.append(request))
    try:
        result = orchestrator.run_workflow(page, "Inspect", max_actions=2)
    finally:
        browser.close()
        playwright.stop()
    assert result["status"] == "blocked"
    assert result["stage"] == "sanitization"
    assert result["redaction_status"] == "incomplete"
    assert calls == []


@pytest.mark.parametrize("candidate", [
    {"type": "not-an-action"},
    {"type": "done", "debug": "unsupported"},
])
def test_malformed_model_actions_are_rejected(monkeypatch, candidate):
    playwright, browser, page = _page()
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: candidate)
    try:
        result = orchestrator.run_workflow(page, "Inspect")
    finally:
        browser.close()
        playwright.stop()
    assert result["status"] == "error"
    assert result["stage"] == "agent"


def test_missing_element_id_and_consequential_click_are_blocked(monkeypatch):
    playwright, browser, page = _page('<button type="submit">Continue</button>')
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: Action(type="click"))
    try:
        missing = orchestrator.run_workflow(page, "Inspect")
        monkeypatch.setattr(orchestrator, "call_llm", lambda request: Action(
            type="click", element_id="e1"
        ))
        consequential = orchestrator.run_workflow(page, "Inspect")
    finally:
        browser.close()
        playwright.stop()
    assert missing["status"] == "blocked"
    assert missing["stage"] == "validation"
    assert consequential["status"] == "blocked"
    assert consequential["stage"] == "validation"


def test_sanitization_error_never_calls_agent(monkeypatch):
    playwright, browser, page = _page()
    monkeypatch.setattr(orchestrator, "sanitize", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("private")))
    calls = []
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: calls.append(request))
    try:
        result = orchestrator.run_workflow(page, "Inspect")
    finally:
        browser.close()
        playwright.stop()
    assert result["stage"] == "sanitization"
    assert calls == []
    assert "private" not in str(result)


def test_snapshot_and_executor_failures_are_reported_without_exception_text(monkeypatch):
    playwright, browser, page = _page()
    monkeypatch.setattr(orchestrator, "take_snapshot", lambda _page, **kwargs: (_ for _ in ()).throw(RuntimeError("sensitive detail")))
    try:
        snapshot_failure = orchestrator.run_workflow(page, "Inspect")
        monkeypatch.undo()
        monkeypatch.setattr(orchestrator, "call_llm", lambda request: Action(type="scroll"))
        monkeypatch.setattr(orchestrator, "execute_action", lambda *args, **kwargs: (_ for _ in ()).throw(orchestrator.ExecutionError("secret detail")))
        execution_failure = orchestrator.run_workflow(page, "Inspect")
    finally:
        browser.close()
        playwright.stop()
    assert snapshot_failure["stage"] == "snapshot"
    assert "sensitive detail" not in str(snapshot_failure)
    assert execution_failure["stage"] == "execution"
    assert "secret detail" not in str(execution_failure)


def test_egress_canary_failure_is_secret_safe():
    with pytest.raises(EgressBlocked) as error:
        assert_no_sensitive_values({"task": "raw-value"}, ["raw-value"])
    assert "raw-value" not in str(error.value)


def test_detected_value_in_task_blocks_egress(monkeypatch):
    secret = "hidden.user@example.test"
    playwright, browser, page = _page(f'<input value="{secret}">')
    calls = []
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: calls.append(request))
    try:
        result = orchestrator.run_workflow(page, f"Find {secret}")
    finally:
        browser.close()
        playwright.stop()
    assert result["status"] == "blocked"
    assert result["stage"] == "egress"
    assert secret not in str(result)
    assert calls == []


@pytest.mark.parametrize("task,secret", [
    ("Use password hunter2 to sign in", "hunter2"),
    ("Use password: S3cret! to sign in", "S3cret"),
    ("Use token=tok_abc123 to continue", "tok_abc123"),
])
def test_credential_in_task_is_redacted_before_agent(monkeypatch, task, secret):
    playwright, browser, page = _page()
    calls = []
    original = orchestrator.call_llm
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: (calls.append(request), original(request))[1])
    try:
        result = orchestrator.run_workflow(page, task)
    finally:
        browser.close()
        playwright.stop()
    assert result["status"] == "completed"
    assert secret not in json.dumps(calls)
    assert "[REDACTED:CREDENTIAL]" in calls[0]["task"]


def test_ambiguous_multword_credential_task_fails_closed(monkeypatch):
    playwright, browser, page = _page()
    calls = []
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: calls.append(request))
    try:
        result = orchestrator.run_workflow(page, "Use password red fox to sign in")
    finally:
        browser.close()
        playwright.stop()
    assert result["status"] == "error"
    assert result["stage"] == "egress"
    assert "red fox" not in str(result)
    assert calls == []


def test_sensitive_input_name_is_not_sent_to_agent(monkeypatch):
    secret_name = "private.user@example.test"
    playwright, browser, page = _page(
        f'<input name="{secret_name}" value="ordinary">'
    )
    requests = []
    original = orchestrator.call_llm
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: (requests.append(request), original(request))[1])
    try:
        result = orchestrator.run_workflow(page, "Inspect this page")
    finally:
        browser.close()
        playwright.stop()
    assert result["status"] == "completed"
    assert secret_name not in json.dumps(requests)
    assert "name" not in requests[0]["elements"][0]


def test_sensitive_hostname_is_not_sent_to_agent(monkeypatch):
    playwright = sync_playwright().start()
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 800, "height": 600})
    page.route("https://alice-secret.privacylens.test/**", lambda route: route.fulfill(
        status=200, content_type="text/html", body="<main>Safe</main>"
    ))
    page.goto("https://alice-secret.privacylens.test/")
    requests = []
    original = orchestrator.call_llm
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: (requests.append(request), original(request))[1])
    try:
        result = orchestrator.run_workflow(page, "Inspect")
    finally:
        browser.close()
        playwright.stop()
    assert result["status"] == "completed"
    assert "alice-secret" not in json.dumps(requests)
    assert all("url" not in request for request in requests)


def test_snapshot_timeout_is_configured_and_failure_blocks_agent(monkeypatch):
    playwright, browser, page = _page()
    calls = []
    seen = []
    real_snapshot = orchestrator.take_snapshot
    real_screenshot = page.screenshot
    screenshot_timeouts = []

    def capture_screenshot(**kwargs):
        screenshot_timeouts.append(kwargs.get("timeout"))
        return real_screenshot(**kwargs)

    monkeypatch.setattr(page, "screenshot", capture_screenshot)

    def capture_snapshot(target, timeout_ms):
        seen.append(timeout_ms)
        return real_snapshot(target, timeout_ms=timeout_ms)

    monkeypatch.setattr(orchestrator, "take_snapshot", capture_snapshot)
    original = orchestrator.call_llm
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: (calls.append(request), original(request))[1])
    try:
        result = orchestrator.run_workflow(page, "Inspect", timeout_ms=1234)
        calls_before_failure = len(calls)
        monkeypatch.setattr(orchestrator, "take_snapshot", lambda target, timeout_ms: (_ for _ in ()).throw(TimeoutError()))
        failed = orchestrator.run_workflow(page, "Inspect", timeout_ms=1234)
    finally:
        browser.close()
        playwright.stop()
    assert seen and all(value == 1234 for value in seen)
    assert screenshot_timeouts and all(value == 1234 for value in screenshot_timeouts)
    assert result["status"] == "completed"
    assert failed["stage"] == "snapshot"
    assert len(calls) == calls_before_failure


def test_execution_limit_and_real_mode_are_explicit(monkeypatch):
    playwright, browser, page = _page()
    try:
        limited = orchestrator.run_workflow(page, "Inspect", max_actions=1)
        real = orchestrator.run_workflow(page, "Inspect", mode="real")
        invalid = orchestrator.run_workflow(page, "Inspect", max_actions=11)
    finally:
        browser.close()
        playwright.stop()
    assert limited["status"] == "action_limit"
    assert len(limited["actions"]) == 1
    assert real["status"] == "error"
    assert "not implemented" in real["message"]
    assert invalid["stage"] == "configuration"


def test_invalid_environment_settings_have_clear_errors():
    with pytest.raises(ConfigurationError, match="PRIVACYLENS_MAX_ACTIONS"):
        Settings.from_env({"PRIVACYLENS_MAX_ACTIONS": "many"})
    assert Settings.from_env({}).max_actions == 5
