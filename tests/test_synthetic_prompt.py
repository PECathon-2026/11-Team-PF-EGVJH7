
import json

from core.agent.prompts import SYSTEM_PROMPT
from core.agent.llm import build_request
from contracts.models import Action, Element, BBox


def test_prompt_supports_synthetic_values():
    assert "synthetic" in SYSTEM_PROMPT.lower()
    assert "private" in SYSTEM_PROMPT.lower()
    assert "approval" in SYSTEM_PROMPT.lower()


def test_action_preserves_synthetic_value():
    synthetic = "alex.smith_482@example.com"

    action = Action(
        type="type",
        element_id="e2",
        text=synthetic,
        reason="Enter the provided test email",
    )

    parsed = Action.model_validate_json(action.model_dump_json())

    assert parsed.text == synthetic
    assert parsed.element_id == "e2"


def test_llm_request_does_not_include_private_mapping():
    element = Element(
        id="e2",
        tag="input",
        type="email",
        value="alex.smith_482@example.com",
        bbox=BBox(x=0, y=0, w=100, h=20),
    )

    view = type("View", (), {
        "url": "http://localhost:8000",
        "title": "Local test",
        "screenshot": b"test-image",
        "elements": [element],
    })()

    request = build_request(
        view=view,
        task="Enter the test email",
        history=[],
        secret_names=[],
    )

    serialized = json.dumps(request)

    assert "alex.smith_482@example.com" in serialized
    assert "synthetic_map" not in serialized
    assert "real_value_map" not in serialized


def test_action_schema_still_rejects_unknown_action():
    try:
        Action.model_validate({
            "type": "execute_arbitrary_code",
            "reason": "invalid",
        })
    except Exception:
        return

    raise AssertionError("Unknown action type should be rejected")
