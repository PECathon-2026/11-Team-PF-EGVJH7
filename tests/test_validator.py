
from contracts.models import Action, Element, SanitizedView
from core.agent.validator import validate


def make_view(url="http://localhost:8000", elements=None):
    return SanitizedView(
        url=url,
        title="Local test page",
        screenshot=b"test",
        screenshot_sha256="test-hash",
        elements=elements or [],
        report=[],
    )


def test_rejects_action_incompatible_with_element():
    view = make_view(elements=[
        Element(id="e1", tag="input", type="text"),
    ])

    result = validate(
        Action(type="click", element_id="e1"),
        view,
        allowed_domains=["localhost"],
        vault_names=set(),
    )

    assert not result.ok


def test_rejects_non_allowlisted_current_domain():
    view = make_view(url="https://example.com")

    result = validate(
        Action(type="done"),
        view,
        allowed_domains=["localhost"],
        vault_names=set(),
    )

    assert not result.ok


def test_rejects_non_allowlisted_navigation():
    view = make_view()

    result = validate(
        Action(type="navigate", url="https://example.com"),
        view,
        allowed_domains=["localhost"],
        vault_names=set(),
    )

    assert not result.ok


def test_rejects_unknown_secret_reference():
    view = make_view(elements=[
        Element(id="e1", tag="input", type="password"),
    ])

    result = validate(
        Action(type="type", element_id="e1", secret_ref="UNKNOWN_SECRET"),
        view,
        allowed_domains=["localhost"],
        vault_names={"SAVED_PASSWORD"},
    )

    assert not result.ok


def test_accepts_existing_secret_reference():
    view = make_view(elements=[
        Element(id="e1", tag="input", type="password"),
    ])

    result = validate(
        Action(type="type", element_id="e1", secret_ref="SAVED_PASSWORD"),
        view,
        allowed_domains=["localhost"],
        vault_names={"SAVED_PASSWORD"},
    )

    assert result.ok


def test_payment_submit_click_requires_approval():
    view = make_view(elements=[
        Element(
            id="e1",
            tag="button",
            text="Submit payment",
        ),
    ])

    result = validate(
        Action(type="click", element_id="e1"),
        view,
        allowed_domains=["localhost"],
        vault_names=set(),
    )

    assert result.ok
    assert result.needs_approval


def test_ordinary_button_does_not_require_approval():
    view = make_view(elements=[
        Element(id="e1", tag="button", text="Continue"),
    ])

    result = validate(
        Action(type="click", element_id="e1"),
        view,
        allowed_domains=["localhost"],
        vault_names=set(),
    )

    assert result.ok
    assert not result.needs_approval
