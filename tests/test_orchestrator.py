
from types import SimpleNamespace

from contracts.models import Action, GuardResult, SanitizedView, ValidationResult
import core.orchestrator as orchestrator


def test_denied_approval_prevents_execution(monkeypatch):
    view = SanitizedView(
        url="http://localhost:8000",
        title="Local test page",
        screenshot=b"sanitized-test-image",
        screenshot_sha256="test-hash",
        elements=[],
        report=[],
    )

    action = Action(
        type="click",
        element_id="e1",
        reason="Submit payment",
    )

    monkeypatch.setattr(
        orchestrator,
        "take_snapshot",
        lambda page: SimpleNamespace(url="http://localhost:8000"),
    )
    monkeypatch.setattr(orchestrator, "detect", lambda snapshot: [])
    monkeypatch.setattr(orchestrator, "sanitize", lambda snapshot, detections: view)
    monkeypatch.setattr(
        orchestrator,
        "build_request",
        lambda **kwargs: {"task": "test", "url": view.url},
    )
    monkeypatch.setattr(
        orchestrator,
        "check_egress",
        lambda payload: GuardResult(ok=True),
    )
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: action)
    monkeypatch.setattr(
        orchestrator,
        "validate",
        lambda **kwargs: ValidationResult(ok=True, needs_approval=True),
    )
    monkeypatch.setattr(orchestrator, "request_approval", lambda action: False)

    execution_calls = []
    monkeypatch.setattr(
        orchestrator,
        "execute_action",
        lambda **kwargs: execution_calls.append(kwargs)
        or {"ok": True, "message": "Executed"},
    )

    result = orchestrator.run_task(
        page=object(),
        task="Submit a payment",
        max_steps=1,
    )

    assert result["ok"] is False
    assert "approval" in result["reason"].lower()
    assert execution_calls == []


def test_final_validation_failure_prevents_execution(monkeypatch):
    view = SanitizedView(
        url="http://localhost:8000",
        title="Local test page",
        screenshot=b"sanitized-test-image",
        screenshot_sha256="test-hash",
        elements=[],
        report=[],
    )

    action = Action(
        type="click",
        element_id="e1",
        reason="Submit payment",
    )

    monkeypatch.setattr(
        orchestrator,
        "take_snapshot",
        lambda page: SimpleNamespace(url="http://localhost:8000"),
    )
    monkeypatch.setattr(orchestrator, "detect", lambda snapshot: [])
    monkeypatch.setattr(
        orchestrator, "sanitize", lambda snapshot, detections: view
    )
    monkeypatch.setattr(
        orchestrator,
        "build_request",
        lambda **kwargs: {"task": "test", "url": view.url},
    )
    monkeypatch.setattr(
        orchestrator,
        "check_egress",
        lambda payload: GuardResult(ok=True),
    )
    monkeypatch.setattr(orchestrator, "call_llm", lambda request: action)

    validation_calls = []

    def validate_first_then_fail(**kwargs):
        validation_calls.append(kwargs)
        if len(validation_calls) == 1:
            return ValidationResult(ok=True, needs_approval=True)
        return ValidationResult(
            ok=False,
            needs_approval=False,
            reasons=["Test final validation failure"],
        )

    monkeypatch.setattr(
        orchestrator, "validate", validate_first_then_fail
    )
    monkeypatch.setattr(
        orchestrator, "request_approval", lambda action: True
    )

    execution_calls = []
    monkeypatch.setattr(
        orchestrator,
        "execute_action",
        lambda **kwargs: execution_calls.append(kwargs)
        or {"ok": True, "message": "Executed"},
    )

    result = orchestrator.run_task(
        page=object(),
        task="Submit a payment",
        max_steps=1,
    )

    assert len(validation_calls) == 2
    assert result["ok"] is False
    assert "validation" in result["reason"].lower()
    assert execution_calls == []
