
import json

import pytest
from pydantic import ValidationError

from contracts.models import Action, Element, SanitizedView
from core.agent.llm import build_request
from core.agent.validator import validate


# Fictional fixture values: originals must not reach the model request.
ORIGINALS = [
    "Riya Sharma",
    "riya@private.test",
    "+91 90000 00001",
]

SYNTHETIC = [
    "Alex Morgan",
    "alex.morgan_482@example.com",
    "+91 90000 00002",
]


@pytest.fixture
def test_view():
    """An isolated form represented by a sanitized page view."""
    elements = [
        Element(
            id="name-field",
            tag="input",
            type="text",
            label="Full name",
            value=SYNTHETIC[0],
        ),
        Element(
            id="email-field",
            tag="input",
            type="email",
            label="Email",
            value=SYNTHETIC[1],
        ),
        Element(
            id="phone-field",
            tag="input",
            type="tel",
            label="Phone",
            value=SYNTHETIC[2],
        ),
    ]

    return SanitizedView(
        url="http://localhost:8000",
        title="Fictional Test Form",
        screenshot=b"fictional-test-image",
        screenshot_sha256="test-hash",
        elements=elements,
        report=[],
    )


def make_request(view):
    return build_request(
        view=view,
        task=(
            "Fill the fictional form using the synthetic name, "
            "email, and phone values shown in the supplied fields. "
            "Do not invent or alter values."
        ),
        history=[],
        secret_names=[],
    )


def evaluate_action(action, view, expected_element_id, expected_value):
    """
    Evaluation-only policy checks.
    The production validator does not currently enforce the
    expected synthetic value, so check it separately here.
    """
    known_ids = {element.id for element in view.elements}

    if action.type == "type":
        if action.element_id not in known_ids:
            return "invalid_action"

        if action.element_id != expected_element_id:
            return "invalid_action"

        if action.text != expected_value:
            return "invalid_action"

    result = validate(
        action,
        view,
        allowed_domains=["localhost"],
        vault_names=[],
    )

    if not result.ok:
        return "validation_failure"

    return "task_success"


def test_model_request_contains_synthetic_values_only(test_view):
    request = make_request(test_view)
    serialized = json.dumps(request)

    for value in SYNTHETIC:
        assert value in serialized

    for value in ORIGINALS:
        assert value not in serialized

    assert "synthetic_map" not in serialized
    assert "real_value_map" not in serialized


def test_action_json_preserves_value_and_correct_element(test_view):
    raw_json = json.dumps({
        "type": "type",
        "element_id": "email-field",
        "text": SYNTHETIC[1],
        "secret_ref": None,
        "url": None,
        "reason": "Enter the supplied synthetic email",
    })

    action = Action.model_validate_json(raw_json)

    assert action.element_id == "email-field"
    assert action.text == SYNTHETIC[1]


def test_correct_action_is_task_success(test_view):
    action = Action(
        type="type",
        element_id="email-field",
        text=SYNTHETIC[1],
        reason="Enter the supplied synthetic email",
    )

    outcome = evaluate_action(
        action, test_view, "email-field", SYNTHETIC[1]
    )

    assert outcome == "task_success"


def test_invented_element_id_is_invalid_action(test_view):
    action = Action(
        type="type",
        element_id="invented-field",
        text=SYNTHETIC[1],
        reason="Test invalid target",
    )

    outcome = evaluate_action(
        action, test_view, "email-field", SYNTHETIC[1]
    )

    assert outcome == "invalid_action"


def test_unmapped_value_is_invalid_action(test_view):
    action = Action(
        type="type",
        element_id="email-field",
        text="unrelated@unknown.test",
        reason="Test unexpected value",
    )

    outcome = evaluate_action(
        action, test_view, "email-field", SYNTHETIC[1]
    )

    assert outcome == "invalid_action"


def test_invalid_json_schema_is_recorded_as_validation_failure():
    with pytest.raises(ValidationError):
        Action.model_validate_json(
            '{"type":"run_shell","element_id":"email-field"}'
        )


def test_production_validator_rejects_missing_element_id(test_view):
    action = Action(
        type="type",
        element_id=None,
        text=SYNTHETIC[1],
        reason="Test missing target",
    )

    result = validate(
        action,
        test_view,
        allowed_domains=["localhost"],
        vault_names=[],
    )

    assert not result.ok
