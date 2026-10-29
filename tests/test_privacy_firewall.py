"""Security and regression tests for the P3 privacy firewall."""

from io import BytesIO

import pytest
from PIL import Image

from contracts.models import Detection, PageElement, PageSnapshot
from core.guard import (
    detect_canary_leak,
    validate_no_leakage,
    validate_outgoing,
)
from core.guard.privacy_budget import decide_disclosure
from core.sanitize.pipeline import build_model_payload


def png():
    buffer = BytesIO()
    Image.new("RGB", (80, 80), "white").save(buffer, format="PNG")
    return buffer.getvalue()


def snapshot(
    value,
    *,
    attrs=None,
    title="Test page",
    url="https://example.test",
):
    return PageSnapshot(
        url=url,
        title=title,
        screenshot=png(),
        elements=[
            PageElement(
                id="field1",
                tag="input",
                value=value,
                attributes=attrs or {},
                attrs=attrs or {},
                bbox={"x": 1, "y": 1, "w": 10, "h": 10},
            )
        ],
    )


def test_firewall_blocks_secret_in_nested_keys_and_values():
    secret = "PRIVATE-FAKE-123"

    result = validate_no_leakage(
        {"meta": {secret: ["nested"]}},
        [secret],
    )

    assert not result.ok


def test_canary_blocks_nested_metadata():
    marker = "PL_CANARY_FAKE_9001"

    result = detect_canary_leak(
        {"messages": [{"metadata": marker}]},
        [marker],
    )

    assert not result.ok


def test_firewall_fails_closed_for_uninspectable_payload():
    result = validate_outgoing(
        {"content": object()},
        [],
        [],
    )

    assert not result.ok


def test_private_mapping_is_not_serialized_and_authorization_required():
    original = "person@example.test"
    page = snapshot(original)

    detection = Detection(
        element_id="field1",
        field="value",
        type="EMAIL",
        span=(0, len(original)),
    )

    result = build_model_payload(
        page,
        [detection],
        synthetic_factory=lambda kind, value: "person_001@example.test",
    )

    assert original not in repr(result.payload)
    assert "private_mapping" not in result.payload

    with pytest.raises(PermissionError):
        result.private_mapping.restore("person_001@example.test")

    assert (
        result.private_mapping.restore(
            "person_001@example.test",
            allowed=True,
        )
        == original
    )


def test_secret_in_url_is_replaced_globally():
    secret = "person@example.test"

    page = snapshot(
        secret,
        url=f"https://example.test/reset?email={secret}",
    )

    detection = Detection(
        element_id="field1",
        field="value",
        type="EMAIL",
        span=(0, len(secret)),
    )

    result = build_model_payload(
        page,
        [detection],
        synthetic_factory=lambda kind, value: "safe@example.test",
    )

    assert secret not in repr(result.payload)


def test_repeated_original_uses_same_synthetic_value():
    secret = "person@example.test"

    page = snapshot(f"Contact {secret} and {secret}")

    detection = Detection(
        element_id="field1",
        field="value",
        type="EMAIL",
        span=(8, 27),
    )

    result = build_model_payload(
        page,
        [detection],
        synthetic_factory=lambda kind, value: "safe@example.test",
    )

    assert (
        result.payload["elements"][0]["value"].count("safe@example.test")
        == 2
    )


def test_privacy_budget_only_discloses_boolean_status():
    decision = decide_disclosure(
        "EMAIL",
        "check whether the email field is filled",
        field_populated=True,
    )

    assert decision.disclose
    assert decision.representation == "populated=True"
    assert "@" not in decision.representation


def test_high_sensitivity_never_disclosed():
    decision = decide_disclosure(
        "PASSWORD",
        "help me log in",
        field_populated=True,
    )

    assert not decision.disclose
    assert decision.representation == "[PROTECTED]"


@pytest.mark.parametrize("case", range(1000))
def test_one_thousand_generated_secret_leakage_cases(case):
    secret = f"SYNTHETIC-SECRET-{case:04d}-END"

    payload = {
        "outer": [{"text": f"prefix-{secret}-suffix"}],
        "case": case,
    }

    result = validate_no_leakage(payload, [secret])

    assert not result.ok


@pytest.mark.parametrize("case", range(1000))
def test_one_thousand_generated_safe_payload_cases(case):
    secret = f"SYNTHETIC-SECRET-{case:04d}-END"

    payload = {
        "outer": [{"text": f"safe-placeholder-{case}"}],
        "case": case,
    }

    result = validate_no_leakage(payload, [secret])

    assert result.ok


def test_pipeline_blocks_canary_and_never_echoes_marker():
    secret = "customer@example.test"
    marker = "PL_CANARY_INJECTED_ABC123"

    page = snapshot(secret)

    detection = Detection(
        element_id="field1",
        field="value",
        type="EMAIL",
        span=(0, len(secret)),
    )

    with pytest.raises(ValueError, match="Privacy firewall blocked"):
        build_model_payload(
            page,
            [detection],
            synthetic_factory=lambda kind, value: marker,
            canaries=[marker],
        )


def test_firewall_evaluation_metrics_are_correct():
    from core.guard import evaluate_canary_firewall

    metrics = evaluate_canary_firewall(
        [
            {
                "payload": {"text": "leak CANARY-X"},
                "canaries": ["CANARY-X"],
                "expected_leak": True,
            },
            {
                "payload": {"text": "safe"},
                "canaries": ["CANARY-Y"],
                "expected_leak": False,
            },
            {
                "payload": {"text": "safe"},
                "canaries": ["CANARY-Z"],
                "expected_leak": True,
            },
            {
                "payload": {"text": "CANARY-W"},
                "canaries": ["CANARY-W"],
                "expected_leak": False,
            },
        ]
    )

    assert metrics.as_dict() == {
        "injected": 2,
        "detected": 1,
        "blocked": 1,
        "missed": 1,
        "false_positives": 1,
    }


@pytest.mark.parametrize(
    "field",
    ["text", "value", "label", "placeholder", "title"],
)
def test_secret_is_removed_from_every_supported_element_field(field):
    secret = "qa.user@example.test"

    element = PageElement(
        id="field1",
        tag="input",
        **{field: secret},
    )

    page = PageSnapshot(
        url="https://example.test",
        title="Page",
        screenshot=png(),
        elements=[element],
    )

    detection = Detection(
        element_id="field1",
        field=field,
        type="EMAIL",
        span=(0, len(secret)),
    )

    result = build_model_payload(
        page,
        [detection],
        synthetic_factory=lambda kind, value: "qa.synthetic@example.test",
    )

    assert secret not in repr(result.payload)


def test_synthetic_collision_fails_closed():
    first = "first@example.test"
    second = "second@example.test"

    element = PageElement(
        id="field1",
        tag="input",
        text=f"{first} {second}",
    )

    page = PageSnapshot(
        url="https://example.test",
        title="Page",
        screenshot=png(),
        elements=[element],
    )

    detections = [
        Detection(
            element_id="field1",
            field="text",
            type="EMAIL",
            span=(0, len(first)),
        ),
        Detection(
            element_id="field1",
            field="text",
            type="EMAIL",
            span=(
                len(first) + 1,
                len(first) + 1 + len(second),
            ),
        ),
    ]

    with pytest.raises(ValueError, match="collision"):
        build_model_payload(
            page,
            detections,
            synthetic_factory=lambda kind, value: "same@example.test",
        )


def test_password_value_in_dom_attributes_is_scrubbed():
    password = "not-a-real-password-777"

    element = PageElement(
        id="field1",
        tag="input",
        type="password",
        value=password,
        attributes={
            "value": password,
            "data-secret-token": password,
        },
        attrs={
            "value": password,
            "data-secret-token": password,
        },
    )

    page = PageSnapshot(
        url="https://example.test",
        title="Page",
        screenshot=png(),
        elements=[element],
    )

    result = build_model_payload(page, [], task_intent="sign in")

    assert password not in repr(result.payload)