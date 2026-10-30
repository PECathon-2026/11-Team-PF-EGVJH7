"""Cross-language parity: the browser extension's JavaScript detectors must
find exactly the same spans as the Python P2 detectors.

Skipped when Node.js is not installed.
"""

import json
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from contracts.models import Detection
from core.detect.merge import calculate_mosaic_risk
from core.detect.patterns import (
    find_aadhaar, find_api_keys, find_cards, find_email, find_ips,
    find_otp, find_pan, find_phone,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
CLI = REPO_ROOT / "extension" / "tests" / "finders_cli.mjs"

PY_FINDERS = {
    "CARD": find_cards, "AADHAAR": find_aadhaar, "PAN": find_pan,
    "EMAIL": find_email, "PHONE": find_phone, "OTP": find_otp,
    "API_KEY": find_api_keys, "IP": find_ips,
}

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


def _corpus() -> list[str]:
    texts = [
        "Card 4111 1111 1111 1111 exp 12/29",
        "4111-1111-1111-1111 and 4111111111111112",
        "Aadhaar 2341 2341 2346 / PAN ABCDE1234F",
        "Mail test.user@example.com or Ünïcode.user@exämple.in",
        "Call 9876543210, +1 (415) 555-0132 or +91 98765 43210",
        "+91-98765-43210 / +91 9876543210 / 98765 43210 / 09876543210",
        "0091 98765 43210, 12345 67890, 4111 98765 43210, 98765 432101",
        "Your OTP code is 482913",
        "key sk-ABCDEFGHIJKLMNOPQRSTUVWX and AKIAABCDEFGHIJKLMNOP",
        "token eyJhbGciOi.eyJzdWIiOiIx.SflKxwRJSM",
        "server 192.168.1.20 and 999.1.1.1",
    ]
    for page in sorted((REPO_ROOT / "testlab" / "pages").glob("*.html")):
        html = page.read_text(encoding="utf-8-sig")
        texts.extend(re.sub(r"<[^>]+>", "\n", html).splitlines())
        texts.extend(re.findall(r'value="([^"]*)"', html))

    rng = random.Random(2026)
    alphabet = "0123456789" * 4 + " -+().@_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop" + "é"
    words = ["otp", "code", "card", "sk-", "AKIA", "ghp_", "@mail.com", "+91 ", "+91-", "0091 ",
             "98765 43210", "verification "]
    for _ in range(600):
        parts = []
        for _ in range(rng.randint(1, 6)):
            if rng.random() < 0.25:
                parts.append(rng.choice(words))
            parts.append("".join(rng.choice(alphabet) for _ in range(rng.randint(1, 24))))
        texts.append("".join(parts))
    return [t for t in texts if t.strip()]


def _run_cli(payload: dict) -> dict:
    completed = subprocess.run(
        [NODE, str(CLI)],
        input=json.dumps(payload),
        capture_output=True, text=True, encoding="utf-8", timeout=60, check=True,
    )
    return json.loads(completed.stdout)


def test_js_and_python_detectors_agree():
    texts = _corpus()
    js_results = _run_cli({"texts": texts})["spans"]

    mismatches = []
    for text, js in zip(texts, js_results):
        for name, finder in PY_FINDERS.items():
            py_spans = [[start, end] for start, end, _ in finder(text)]
            if py_spans != js[name]:
                mismatches.append((name, text, py_spans, js[name]))

    assert not mismatches, (
        f"{len(mismatches)} parity mismatches, first 5:\n"
        + "\n".join(map(repr, mismatches[:5]))
    )


def test_js_and_python_mosaic_risk_agree():
    rng = random.Random(7)
    types = ["CARD", "AADHAAR", "PAN", "PASSWORD", "API_KEY", "EMAIL", "PHONE",
             "ADDRESS", "PERSON", "IP", "OTP", "SECRET"]
    cases = [
        [{"type": rng.choice(types), "confidence": rng.choice([0.5, 0.75, 1.0, 0.65])}
         for _ in range(rng.randint(0, 14))]
        for _ in range(200)
    ]
    js_scores = _run_cli({"texts": [], "risk": cases})["risk"]
    for case, js_score in zip(cases, js_scores):
        py_score = calculate_mosaic_risk([Detection(**d) for d in case])
        assert js_score == pytest.approx(py_score, abs=0.011), case
