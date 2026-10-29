import pytest

from contracts.models import Action, Element, PageSnapshot
from core.browser.executor import ExecutionError, _validate_navigation_url, execute_action
from core.agent.validator import validate
from contracts.models import SanitizedView


class FakeLocator:
    def __init__(self, count=1, snapshot_id="snap", state=None):
        self._count = count
        self.snapshot_id = snapshot_id
        self.state = state or {
            "tag": "button", "type": "button", "name": None,
            "value": "", "text": "Continue", "placeholder": "",
            "href": "", "disabled": False, "readonly": False,
        }

    def count(self):
        return self._count

    def get_attribute(self, name):
        return self.state.get("href", "") if name == "href" else self.snapshot_id

    def evaluate(self, _script):
        return self.state

    def is_visible(self):
        return True

    def is_enabled(self):
        return True

    def click(self, **_kwargs):
        self.clicked = True


class FakePage:
    def __init__(self, locator):
        self._locator = locator
        self.url = "https://example.test/start"
        self.goto_calls = []

    def locator(self, _selector):
        return self._locator

    def goto(self, url, **_kwargs):
        self.goto_calls.append(url)


def test_navigation_rejects_non_web_schemes_and_embedded_credentials():
    for url in ("javascript:alert(1)", "file:///etc/passwd",
                "https://user:pass@example.test/"):
        with pytest.raises(ExecutionError):
            _validate_navigation_url(url)
    with pytest.raises(ExecutionError):
        _validate_navigation_url("https://[bad-host/")


def test_navigation_policy_rejects_destructive_path_and_allows_safe_url():
    view = SanitizedView(url="", screenshot=b"", screenshot_sha256="", elements=[])
    assert validate(Action(type="navigate", url="https://example.test/help?topic=privacy"), view).ok
    for url in (
        "https://example.test/account/delete",
        "https://example.test/help?operation=delete",
        "https://example.test/help?operation=deleteAccount",
        "https://example.test/help?next=%2Faccount%2Fremove",
    ):
        assert not validate(Action(type="navigate", url=url), view).ok
        page = FakePage(FakeLocator())
        with pytest.raises(ExecutionError):
            execute_action(page, PageSnapshot(url="", screenshot=b"x"), Action(type="navigate", url=url))
        assert page.goto_calls == []


def test_neutral_link_with_destructive_query_is_not_clicked():
    locator = FakeLocator(snapshot_id="snap", state={
        "tag": "a", "type": None, "name": None, "value": "", "text": "Help",
        "placeholder": "", "href": "/help?operation=delete", "disabled": False,
        "readonly": False,
    })
    snapshot = PageSnapshot(url="https://example.test/start", screenshot=b"x", snapshot_id="snap",
        elements=[Element(id="e1", tag="a", text="Help", attrs={"href": "/help?operation=delete"})])
    page = FakePage(locator)
    with pytest.raises(ExecutionError, match="consequential"):
        execute_action(page, snapshot, Action(type="click", element_id="e1"))
    assert not getattr(locator, "clicked", False)


def test_stale_snapshot_is_rejected_before_click():
    snapshot = PageSnapshot(
        url="https://example.test", screenshot=b"x",
        snapshot_id="old", elements=[Element(
            id="e1", tag="button", type="button", text="Continue"
        )],
    )
    page = FakePage(FakeLocator(snapshot_id="new"))
    with pytest.raises(ExecutionError, match="stale"):
        execute_action(page, snapshot, Action(type="click", element_id="e1"))


def test_changed_target_is_stale_even_if_snapshot_token_matches():
    snapshot = PageSnapshot(
        url="https://example.test", screenshot=b"x", snapshot_id="snap",
        elements=[Element(id="e1", tag="button", type="button", text="Continue")],
    )
    page = FakePage(FakeLocator(state={
        "tag": "button", "type": "button", "name": None,
        "value": "", "text": "Delete account", "placeholder": "",
        "href": "", "disabled": False, "readonly": False,
    }))
    with pytest.raises(ExecutionError, match="stale"):
        execute_action(page, snapshot, Action(type="click", element_id="e1"))


def test_submit_control_is_blocked_even_without_risky_label():
    snapshot = PageSnapshot(
        url="https://example.test", screenshot=b"x", snapshot_id="snap",
        elements=[Element(id="e1", tag="button", type="submit", text="Continue")],
    )
    page = FakePage(FakeLocator(state={
        "tag": "button", "type": "submit", "name": None,
        "value": "", "text": "Continue", "placeholder": "",
        "href": "", "disabled": False, "readonly": False,
    }))
    with pytest.raises(ExecutionError, match="submission"):
        execute_action(page, snapshot, Action(type="click", element_id="e1"))


def test_script_backed_button_is_blocked_even_with_neutral_label():
    snapshot = PageSnapshot(
        url="https://example.test", screenshot=b"x", snapshot_id="snap",
        elements=[Element(id="e1", tag="button", type="button", text="Continue")],
    )
    page = FakePage(FakeLocator())
    with pytest.raises(ExecutionError, match="Script-backed"):
        execute_action(page, snapshot, Action(type="click", element_id="e1"))
