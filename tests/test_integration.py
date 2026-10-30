"""End-to-end integration tests against the local testlab checkout page.

P1 snapshot -> P2 detection -> P3 synthetic substitution -> P4 action
validation -> P1 execution, using a real headless Chromium and the real
testlab HTTP server (see tests/conftest.py).
"""

import random
import re

import pytest

from contracts.models import Action
from core import orchestrator
from core.agent.validator import validate
from core.browser.executor import ExecutionError, execute_action
from core.browser.snapshot import take_snapshot
from core.detect import detect, synthetic
from core.detect.patterns import find_cards
from core.detect.synthetic import get_synthetic_value
from core.detect.validators import luhn_ok
from core.sanitize import sanitize
from core.sanitize.pipeline import build_model_payload


REAL_CARD = "4111 1111 1111 1111"

TRACK_PAY_CLICKS_JS = """() => {
    window.__payClicks = 0;
    document.querySelector('#pay')
        .addEventListener('click', () => { window.__payClicks += 1; });
}"""


@pytest.fixture
def deterministic_synthetics(monkeypatch):
    """Fresh synthetic cache and a fixed RNG seed, restored afterwards.

    The CVV generator picks a random 3-digit value; a fixed seed keeps it
    from ever coinciding with the real CVV and making this test flaky.
    """

    monkeypatch.setattr(synthetic, "_SYNTH_CACHE", {})
    state = random.getstate()
    random.seed(2026)
    try:
        yield
    finally:
        random.setstate(state)


@pytest.fixture
def synthetic_rules(tmp_path):
    """Rules without the hard-redact selectors for card fields.

    The shipped rules.yaml lists [autocomplete='cc-number'] and
    [autocomplete='cc-csc'] under always_redact_selectors, which replaces the
    whole field with [REDACTED:SECRET] before synthetic substitution can run.
    This rules file isolates the P2/P3 synthetic-card path.
    """

    path = tmp_path / "rules.yaml"
    path.write_text("always_redact_selectors: []\nnever_redact: []\n", encoding="utf-8")
    return str(path)


def _element(snapshot, name):
    return next(element for element in snapshot.elements if element.name == name)


def _pay_button(snapshot):
    return next(element for element in snapshot.elements if element.text == "Pay Now")


def test_p2_detects_real_card(checkout_page):
    snapshot = take_snapshot(checkout_page)
    card = _element(snapshot, "card")
    assert card.value == REAL_CARD

    detections = detect(snapshot)
    card_hits = [
        d for d in detections
        if d.type == "CARD" and d.element_id == card.id and d.field == "value"
    ]
    assert card_hits, "P2 did not flag the card field."

    for hit in card_hits:
        start, end = hit.span
        assert card.value[start:end] == REAL_CARD
        assert luhn_ok(re.sub(r"\D", "", card.value[start:end]))


def test_p3_replaces_card_with_synthetic_luhn_valid_card(
    checkout_page, deterministic_synthetics, synthetic_rules
):
    snapshot = take_snapshot(checkout_page)
    card_id = _element(snapshot, "card").id

    model = build_model_payload(
        snapshot,
        detect(snapshot),
        synthetic_factory=get_synthetic_value,
        rules_path=synthetic_rules,
    )

    card_out = next(e for e in model.payload["elements"] if e["id"] == card_id)
    fake = card_out["value"]
    fake_digits = re.sub(r"\D", "", fake)

    assert fake != REAL_CARD
    assert fake_digits != re.sub(r"\D", "", REAL_CARD)
    assert re.fullmatch(r"\d{4} \d{4} \d{4} \d{4}", fake)
    assert luhn_ok(fake_digits), "Synthetic card must pass the Luhn checksum."

    # The synthetic card is realistic enough that P2 itself still sees a card.
    assert find_cards(fake)

    # The real value is nowhere in the outgoing payload, including attributes.
    assert REAL_CARD not in str(model.payload)
    assert "4111111111111111" not in str(model.payload)

    # Only the trusted side can map the synthetic value back, and only with
    # explicit authorization.
    with pytest.raises(PermissionError):
        model.private_mapping.restore(fake)
    assert model.private_mapping.restore(fake, allowed=True) == REAL_CARD


def test_p3_default_rules_never_emit_real_card(checkout_page, deterministic_synthetics):
    """With the shipped rules.yaml the card field is hard-redacted instead."""

    snapshot = take_snapshot(checkout_page)
    card_id = _element(snapshot, "card").id

    model = build_model_payload(
        snapshot,
        detect(snapshot),
        synthetic_factory=get_synthetic_value,
    )

    card_out = next(e for e in model.payload["elements"] if e["id"] == card_id)
    assert card_out["value"] == "[REDACTED:SECRET]"
    assert REAL_CARD not in str(model.payload)
    assert "4111111111111111" not in str(model.payload)


def test_executor_physically_blocks_pay_without_approval(checkout_page):
    checkout_page.evaluate(TRACK_PAY_CLICKS_JS)
    snapshot = take_snapshot(checkout_page)
    pay = _pay_button(snapshot)
    action = Action(type="click", element_id=pay.id, reason="Complete purchase")

    # P4 validator rejects it before execution.
    view = sanitize(snapshot, detect(snapshot))
    assert not validate(action, view).ok

    # P1 executor independently refuses, even when called directly.
    with pytest.raises(ExecutionError, match="approval"):
        execute_action(checkout_page, snapshot, action)

    assert checkout_page.evaluate("window.__payClicks") == 0
    assert checkout_page.url.endswith("/checkout.html")


def _agent_that_clicks_pay(request):
    pay = next(e for e in request["elements"] if e.get("text") == "Pay Now")
    return Action(type="click", element_id=pay["id"], reason="Pay for the order")


def test_full_loop_blocks_agent_pay_click(checkout_page, monkeypatch):
    checkout_page.evaluate(TRACK_PAY_CLICKS_JS)
    monkeypatch.setattr(orchestrator, "call_llm", _agent_that_clicks_pay)

    result = orchestrator.run_workflow(checkout_page, "Buy the item", max_actions=3)

    assert result["status"] == "blocked"
    assert result["stage"] == "validation"
    assert result["actions"] == []
    assert checkout_page.evaluate("window.__payClicks") == 0


def test_executor_blocks_pay_even_if_validator_is_bypassed(checkout_page, monkeypatch):
    """Defense in depth: a buggy or compromised validator is not enough."""

    checkout_page.evaluate(TRACK_PAY_CLICKS_JS)
    monkeypatch.setattr(orchestrator, "call_llm", _agent_that_clicks_pay)
    monkeypatch.setattr(
        orchestrator,
        "validate",
        lambda action, view: validate(Action(type="done"), view),
    )

    result = orchestrator.run_workflow(checkout_page, "Buy the item", max_actions=3)

    assert result["status"] == "blocked"
    assert result["stage"] == "execution"
    assert checkout_page.evaluate("window.__payClicks") == 0
