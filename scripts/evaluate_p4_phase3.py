"""P4 Phase 3: Controlled agent task-success evaluation.

Uses fictional test data and makes live LLM calls.
Does not launch a browser or submit a form.
"""

import json
import sys
from collections import Counter
from hashlib import sha256
from io import BytesIO

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from PIL import Image

from contracts.models import Action, Element, SanitizedView
from core.agent.llm import build_request, call_llm
from core.agent.validator import validate


# Fictional values only — never use real personal information.
SYNTHETIC = {
    "name": "Alex Morgan",
    "email": "alex.morgan_482@example.com",
    "phone": "+91 90000 00002",
}

# Fictional markers used to check that originals are not sent to the model.
FIXTURE_ORIGINALS = [
    "Riya Sharma",
    "riya@private.test",
    "+91 90000 00001",
]

CASES = [
    {
        "field": "name",
        "element_id": "name-field",
        "input_type": "text",
        "label": "Full name",
    },
    {
        "field": "email",
        "element_id": "email-field",
        "input_type": "email",
        "label": "Email address",
    },
    {
        "field": "phone",
        "element_id": "phone-field",
        "input_type": "tel",
        "label": "Phone number",
    },
]


def make_test_screenshot():
    """Create a blank PNG for the fictional test page."""
    image = Image.new("RGB", (640, 360), "white")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def make_view():
    """Build a sanitized view with three fictional input fields."""
    elements = [
        Element(
            id=case["element_id"],
            tag="input",
            type=case["input_type"],
            label=case["label"],
            value="",
        )
        for case in CASES
    ]

    screenshot = make_test_screenshot()

    return SanitizedView(
        url="http://localhost:8000",
        title="Fictional Agent Evaluation Form",
        screenshot=screenshot,
        screenshot_sha256=sha256(screenshot).hexdigest(),
        elements=elements,
        report=[],
    )


def evaluate_case(view, case):
    """Call the model and classify the result for one fictional field."""
    expected_value = SYNTHETIC[case["field"]]

    task = (
        f"On the fictional test form, enter exactly {expected_value!r} "
        f"into the {case['label']} field. "
        f"Use element ID {case['element_id']!r}. "
        "Do not submit the form or navigate away."
    )

    request = build_request(
        view=view,
        task=task,
        history=[],
        secret_names=[],
    )

    # Basic check that fictional original markers are absent from the request.
    serialized_request = json.dumps(request, ensure_ascii=False)

    if any(original in serialized_request for original in FIXTURE_ORIGINALS):
        return (
            "validation_failure",
            "A fixture original was found in the model request.",
        )

    # Make a live LLM call.
    action = call_llm(request)

    if not isinstance(action, Action):
        return "validation_failure", "The model did not return an Action."

    # Evaluate the exact action expected for this test case.
    if (
        action.type != "type"
        or action.element_id != case["element_id"]
        or action.text != expected_value
        or action.secret_ref is not None
    ):
        return (
            "invalid_action",
            (
                f"action_type={action.type}; "
                f"target_matches={action.element_id == case['element_id']}; "
                f"value_matches={action.text == expected_value}"
            ),
        )

    # Run the project's existing production validator.
    result = validate(
        action,
        view,
        allowed_domains=["localhost"],
        vault_names=[],
    )

    if not result.ok:
        return (
            "validation_failure",
            "; ".join(result.reasons),
        )

    return (
        "task_success",
        "Expected action produced and production validation passed.",
    )


def main():
    view = make_view()
    outcomes = Counter()

    print("P4 Phase 3 — Fictional Task-Success Evaluation")
    print("Cases: name, email, phone")
    print("No browser interaction or form submission will occur.")

    for case in CASES:
        print(f"\nEvaluating field: {case['field']}")

        try:
            category, detail = evaluate_case(view, case)
        except Exception as exc:
            # Avoid printing request contents or credentials.
            category = "validation_failure"
            detail = (
                f"Evaluation did not complete ({type(exc).__name__}). "
                "Check local configuration and the error details privately."
            )

        outcomes[category] += 1
        print(f"Category: {category}")
        print(f"Detail: {detail}")

    print("\n=== P4 Phase 3 Summary ===")

    for category in (
        "task_success",
        "invalid_action",
        "validation_failure",
    ):
        print(f"{category}: {outcomes[category]}")

    print(f"total_cases: {len(CASES)}")
    print("Results represent live model calls, not mocked tests.")


if __name__ == "__main__":
    main()