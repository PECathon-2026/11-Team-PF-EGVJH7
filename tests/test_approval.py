
from types import SimpleNamespace

from core.agent.approval import request_approval


def test_approval_accepts_exact_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "YES")
    action = SimpleNamespace(
        type="click",
        element_id="e1",
        reason="Submit payment",
    )

    assert request_approval(action) is True


def test_approval_rejects_lowercase_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    action = SimpleNamespace(
        type="click",
        element_id="e1",
        reason="Submit payment",
    )

    assert request_approval(action) is False


def test_approval_rejects_no(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "NO")
    action = SimpleNamespace(
        type="click",
        element_id="e1",
        reason="Submit payment",
    )

    assert request_approval(action) is False


def test_approval_rejects_eof(monkeypatch):
    def raise_eof(_):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    action = SimpleNamespace(
        type="click",
        element_id="e1",
        reason="Submit payment",
    )

    assert request_approval(action) is False
