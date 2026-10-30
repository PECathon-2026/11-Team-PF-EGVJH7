"""Automated canary leakage tests for the P1 -> P2 -> P3 -> agent pipeline.

Each trial generates fresh, random canary secrets that are mathematically
valid instances of the types PrivacyLens must protect (Luhn-valid card,
Verhoeff-valid Aadhaar, PAN, API key, email), injects them into the local
checkout page, runs the real pipeline, and checks three properties:

1. Precondition: every canary is present in P1's raw snapshot, so the
   trial genuinely exercised the sanitizer.
2. Postcondition: no canary, in any of its formatting variants, appears in
   the serialized JSON that would leave the process.
3. Oracle sensitivity: the leak detectors flag the canaries when they ARE
   present, so a passing result is not vacuous.

Limitation: these are string-level checks. The screenshot is included in
the searched payload as base64, but text rendered as pixels is not OCR'd.
"""

import json
import random
import re
import string
from io import BytesIO

import pytest
from PIL import Image

from contracts.models import Element, PageSnapshot
from core import orchestrator
from core.browser.snapshot import take_snapshot
from core.detect import detect
from core.detect.synthetic import get_synthetic_value
from core.detect.validators import _D, _INV, _P, luhn_ok, verhoeff_ok
from core.guard import detect_canary_leak, validate_outgoing
from core.sanitize.pipeline import build_model_payload
from core.sanitize.rules import placeholder_for


BROWSER_TRIALS = 5
IN_MEMORY_TRIALS = 200


def synthetic_or_placeholder(dtype: str, secret: str) -> str:
    """Synthetic value where P2 has a generator, typed placeholder otherwise.

    get_synthetic_value() raises for AADHAAR, PAN, API_KEY, etc., which makes
    build_model_payload() fail closed on any page containing one of them.
    """

    try:
        return get_synthetic_value(dtype, secret)
    except ValueError:
        return placeholder_for(dtype)


# --- Canary generators -------------------------------------------------------

def _luhn_card(rng: random.Random) -> str:
    partial = "4" + "".join(rng.choice(string.digits) for _ in range(14))
    for check in string.digits:
        if luhn_ok(partial + check):
            digits = partial + check
            break
    return " ".join(digits[i:i + 4] for i in range(0, 16, 4))


def _verhoeff_aadhaar(rng: random.Random) -> str:
    payload = rng.choice("23456789") + "".join(
        rng.choice(string.digits) for _ in range(10)
    )
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    digits = payload + str(_INV[c])
    assert verhoeff_ok(digits)
    return f"{digits[:4]} {digits[4:8]} {digits[8:]}"


def _pan(rng: random.Random) -> str:
    return (
        "".join(rng.choice(string.ascii_uppercase) for _ in range(5))
        + "".join(rng.choice(string.digits) for _ in range(4))
        + rng.choice(string.ascii_uppercase)
    )


def _api_key(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits
    return "sk-" + "".join(rng.choice(alphabet) for _ in range(32))


def _email(rng: random.Random) -> str:
    tag = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    return f"canary.{tag}@leak-canary.test"


def make_canaries(seed: int) -> dict[str, str]:
    rng = random.Random(seed)
    return {
        "card": _luhn_card(rng),
        "aadhaar": _verhoeff_aadhaar(rng),
        "pan": _pan(rng),
        "api_key": _api_key(rng),
        "email": _email(rng),
        "notes_email": _email(rng),
    }


def variants(value: str) -> set[str]:
    """A canary plus the reformatted spellings a leak could take."""

    found = {value, value.lower(), value.upper()}
    compact = re.sub(r"[\s-]", "", value)
    if compact.isdigit():
        found.add(compact)
        found.add("-".join(compact[i:i + 4] for i in range(0, len(compact), 4)))
    return found


def leaked(blob: str, canaries: dict[str, str]) -> dict[str, list[str]]:
    hits = {}
    for name, value in canaries.items():
        matches = sorted(v for v in variants(value) if v in blob)
        if matches:
            hits[name] = matches
    return hits


# --- Browser-level injection -------------------------------------------------

INJECT_CANARIES_JS = """(c) => {
    const set = (sel, v) => {
        const el = document.querySelector(sel);
        el.setAttribute('value', v);
        el.value = v;
    };
    set('#card', c.card);
    set('#email', c.email);

    // Neutral labels: these must be caught by P2's regex + checksum
    // validators, not by structural hints such as name="card".
    const form = document.querySelector('form');
    const add = (html) => form.insertAdjacentHTML('beforeend', html);
    add(`<label for="ref1">Reference</label>
         <input id="ref1" name="ref1" type="text" value="${c.pan}">`);
    add(`<label for="ref2">Customer number</label>
         <input id="ref2" name="ref2" type="text" value="${c.aadhaar}">`);
    add(`<label for="ref3">Integration</label>
         <input id="ref3" name="ref3" type="text" value="${c.api_key}">`);
    add(`<label for="notes">Notes</label>
         <textarea id="notes" name="notes">Receipt to ${c.notes_email} please</textarea>`);
}"""


@pytest.fixture
def canary_page(checkout_page):
    def inject(canaries: dict[str, str]):
        checkout_page.evaluate(INJECT_CANARIES_JS, canaries)
        return checkout_page

    return inject


@pytest.mark.parametrize("seed", range(BROWSER_TRIALS))
def test_canaries_never_reach_agent_request(canary_page, monkeypatch, seed):
    """Full orchestrator loop: nothing sent to the (mock) LLM contains a canary."""

    canaries = make_canaries(seed)
    page = canary_page(canaries)

    raw = take_snapshot(page).model_dump_json(exclude={"screenshot"})
    assert leaked(raw, canaries).keys() == canaries.keys(), (
        "Precondition failed: P1 did not capture every injected canary."
    )

    captured = []
    real_agent = orchestrator.call_llm

    def spy(request):
        captured.append(json.loads(json.dumps(request)))
        return real_agent(request)

    monkeypatch.setattr(orchestrator, "call_llm", spy)

    result = orchestrator.run_workflow(page, "Review the checkout page", max_actions=3)

    assert result["status"] == "completed", result
    assert result["detection_count"] > 0
    assert captured, "Agent was never called, so no egress was exercised."

    outgoing = json.dumps(captured)
    assert leaked(outgoing, canaries) == {}


@pytest.mark.parametrize("seed", range(BROWSER_TRIALS))
def test_canaries_never_reach_model_payload(canary_page, seed):
    """P3 model payload with synthetic substitution contains no canary."""

    canaries = make_canaries(1000 + seed)
    page = canary_page(canaries)

    snapshot = take_snapshot(page)
    detections = detect(snapshot)
    model = build_model_payload(
        snapshot,
        detections,
        synthetic_factory=synthetic_or_placeholder,
    )

    outgoing = json.dumps(model.payload)
    assert leaked(outgoing, canaries) == {}

    # The library's own fail-closed guard must agree with the independent check.
    protected = sorted({v for c in canaries.values() for v in variants(c)})
    assert validate_outgoing(model.payload, protected).ok
    assert detect_canary_leak(model.payload, protected).ok

    # The trusted-side mapping must still be able to restore every original
    # value that was substituted (it stays local and is never serialized).
    restorable = set(model.private_mapping.synthetic_to_original.values())
    for name in ("card", "email", "aadhaar", "pan", "api_key"):
        assert any(canaries[name] in original for original in restorable), name


def test_oracle_detects_unsanitized_canaries(canary_page):
    """Negative control: the same checks fail on the raw P1 snapshot."""

    canaries = make_canaries(424242)
    snapshot = take_snapshot(canary_page(canaries))
    raw_payload = json.loads(snapshot.model_dump_json(exclude={"screenshot"}))

    assert leaked(json.dumps(raw_payload), canaries).keys() == canaries.keys()

    protected = list(canaries.values())
    guard = validate_outgoing(raw_payload, protected)
    assert not guard.ok
    assert set(guard.leaks) == set(protected)
    # Guard reasons must never echo the secrets they found.
    assert leaked(" ".join(guard.reasons), canaries) == {}

    assert not detect_canary_leak(raw_payload, protected).ok


# --- High-volume in-memory property test -------------------------------------

def _png(width=800, height=600) -> bytes:
    buffer = BytesIO()
    Image.new("RGB", (width, height), "white").save(buffer, format="PNG")
    return buffer.getvalue()


SCANNED_FIELDS = ("value", "text", "label", "placeholder")


def test_random_canaries_in_random_fields_never_leak():
    """Hundreds of randomized snapshots, no browser: zero leaks allowed."""

    screenshot = _png()
    failures = []

    for trial in range(IN_MEMORY_TRIALS):
        rng = random.Random(10_000 + trial)
        canaries = make_canaries(10_000 + trial)

        elements = []
        for index, (name, value) in enumerate(canaries.items()):
            field = rng.choice(SCANNED_FIELDS)
            prefix = rng.choice(["", "Note: ", "ref "])
            tag = "input" if field in {"value", "placeholder"} else "textarea"
            elements.append(Element(
                id=f"e{index + 1}",
                tag=tag,
                type="text" if tag == "input" else None,
                name=f"field{index}",
                bbox={"x": 10, "y": 10 + 40 * index, "w": 300, "h": 30},
                **{field: prefix + value},
            ))

        snapshot = PageSnapshot(
            url="https://privacylens.test/form",
            title="Form",
            screenshot=screenshot,
            elements=elements,
        )

        model = build_model_payload(
            snapshot,
            detect(snapshot),
            synthetic_factory=synthetic_or_placeholder,
        )
        hits = leaked(json.dumps(model.payload), canaries)
        if hits:
            failures.append((trial, sorted(hits)))

    assert failures == [], f"{len(failures)}/{IN_MEMORY_TRIALS} trials leaked: {failures[:5]}"
