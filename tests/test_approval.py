
from types import SimpleNamespace

from contracts.models import Action
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


def test_approval_summary_does_not_print_typed_or_secret_values(
    monkeypatch, capsys
):
    action = Action(
        type="click",
        element_id="submit-button",
        text="fictional-private-value",
        secret_ref="private-secret-reference",
        reason="Sensitive action",
    )

    monkeypatch.setattr("builtins.input", lambda _: "NO")

    assert request_approval(action) is False

    output = capsys.readouterr().out
    assert "fictional-private-value" not in output
    assert "private-secret-reference" not in output
    assert "submit-button" in output
    assert "APPROVAL REQUIRED" in output


def test_approval_accepts_yes_with_surrounding_whitespace(monkeypatch):
    action = Action(
        type="click",
        element_id="submit-button",
        reason="Submit payment",
    )

    monkeypatch.setattr("builtins.input", lambda _: " YES ")

    assert request_approval(action) is True


def test_approval_rejects_empty_response(monkeypatch):
    action = Action(
        type="click",
        element_id="submit-button",
    )

    monkeypatch.setattr("builtins.input", lambda _: "")

    assert request_approval(action) is False
