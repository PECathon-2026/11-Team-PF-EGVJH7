
import base64
from types import SimpleNamespace

from contracts.models import Action, GuardResult, SanitizedView
import core.orchestrator as orchestrator
from core.agent.llm import build_request


def test_orchestrator_sends_sanitized_screenshot(monkeypatch):
    original_screenshot = b"ORIGINAL-UNSANITIZED-SCREENSHOT"
    sanitized_screenshot = b"SANITIZED-SCREENSHOT"

    snapshot = SimpleNamespace(
        url="http://localhost:8000",
        title="Local test",
        screenshot=original_screenshot,
        elements=[],
    )

    view = SanitizedView(
        url="http://localhost:8000",
        title="Local test",
        screenshot=sanitized_screenshot,
        screenshot_sha256="test-hash",
        elements=[],
        report=[],
    )

    captured = {}

    monkeypatch.setattr(
        orchestrator, "take_snapshot", lambda page: snapshot
    )
    monkeypatch.setattr(orchestrator, "detect", lambda snap: [])
    monkeypatch.setattr(
        orchestrator, "sanitize", lambda snap, detections: view
    )
    monkeypatch.setattr(
        orchestrator, "build_request", build_request
    )
    monkeypatch.setattr(
        orchestrator,
        "check_egress",
        lambda payload: GuardResult(ok=True),
    )

    def fake_call_llm(request):
        captured.update(request)
        return Action(type="done", reason="Privacy handoff test")

    monkeypatch.setattr(orchestrator, "call_llm", fake_call_llm)

    result = orchestrator.run_task(
        page=object(),
        task="Check screenshot handoff",
        max_steps=1,
    )

    sent_screenshot = base64.b64decode(captured["screenshot_b64"])

    assert result["ok"] is True
    assert sent_screenshot == sanitized_screenshot
    assert sent_screenshot != original_screenshot
