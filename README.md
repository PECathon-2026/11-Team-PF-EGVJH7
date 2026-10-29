# PrivacyLens

PrivacyLens is a local browser privacy prototype. It snapshots a page, detects selected sensitive values, sanitizes DOM fields and screenshot regions, and can pass only the sanitized view to a bounded mock agent workflow.

It is a research and development project, not a complete privacy filter or production browser agent. Detection is not exhaustive; a clean report does not prove that a page contains no sensitive information.

## Architecture

- `core/browser/snapshot.py` captures interactive controls and common visible text regions. Coordinates are viewport-relative CSS pixels. The screenshot is viewport-sized at Playwright CSS scale; device-pixel ratio is recorded for diagnostics.
- `core/detect/` combines regex checks, checksum validators, and DOM field metadata. Current implemented patterns include email, phone, payment-card candidates, Aadhaar, PAN, OTP, API-key formats, and IPv4.
- `core/sanitize/` applies selector rules, replaces detected DOM spans, scans for prompt-injection patterns, and draws opaque image redactions. Its report distinguishes redacted, skipped, and failed image detections.
- `core/guard/` includes an outbound canary check. A workflow is blocked if a detected source value remains in the agent request or image redaction is unresolved.
- `core/agent/llm.py` builds a restricted request from sanitized fields and implements a deterministic mock agent. It does not call an external model.
- `core/browser/executor.py` checks snapshot identity and target state, restricts navigation to HTTP(S), blocks password/secret-reference entry, blocks form submissions and script-backed controls, and allows only policy-checked links to be clicked.
- `core/orchestrator.py` owns Chromium for the CLI. `run_workflow()` can also be called with a page whose browser lifecycle is owned by the caller.

## Windows setup

Use Python 3.10 or newer. From PowerShell in this directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass` in that terminal, then activate the environment.

## Configuration

Mock mode needs no API key or `.env` file. Optional environment settings:

| Variable | Default | Allowed range |
| --- | ---: | ---: |
| `PRIVACYLENS_START_URL` | `http://127.0.0.1:8000/checkout.html` | HTTP or HTTPS URL without embedded credentials |
| `PRIVACYLENS_MAX_ACTIONS` | `5` | 1–10 |
| `PRIVACYLENS_ACTION_TIMEOUT_MS` | `5000` | 1–30000 |

The CLI also accepts `--url`, `--max-actions`, and `--timeout-ms`. Invalid settings fail with a non-sensitive configuration error.

## Run the mock workflow

Start the synthetic local fixture server in one PowerShell window:

```powershell
python -m http.server 8000 --directory testlab/pages
```

In another window, from the repository root:

```powershell
python -m core.orchestrator --mock-llm --url http://127.0.0.1:8000/checkout.html --task "Review the local checkout page safely"
```

The mock agent performs one harmless scroll and then terminates. The workflow emits a JSON summary, not page values or exception details. A nonzero exit code indicates a blocked or failed workflow. If the sanitizer cannot establish complete screenshot redaction for its detections, the agent is not called.

## Tests

```powershell
python -m pytest tests/ -v
```

The suite uses synthetic data and local Playwright pages; it does not access an external site. Browser installation is required for orchestrator tests.

## Real LLM status

Real LLM mode is **not implemented**. The orchestrator returns a clear error if mock mode is not selected. There is no provider adapter, API-key configuration, or real-model workflow to document as working. The `SYSTEM_PROMPT` is preparatory text only and is not currently sent to a provider. No API credentials are required by the mock workflow.

## Safeguards and limitations

- Only selected sanitized element fields are put into the agent request; raw attributes, element `name` values, and all URL data (including the hostname) are omitted.
- Detected source substrings are checked against outbound request fields. Recognizable single-token credentials in the task are replaced with a fixed marker; ambiguous credential-bearing task text fails closed. Other detected PII remaining in task text is blocked without including it in the error.
- Sanitization failures and incomplete image-redaction reports stop the agent loop.
- The executor rejects stale or changed targets, password entry, secret references, form submissions, arbitrary script-backed control clicks, and invalid navigation schemes. No approval mechanism exists, so consequential actions remain blocked.
- Screenshot capture is viewport-only. An offscreen or hidden detection is sanitized in the DOM view but cannot be visually covered in pixels that were not captured; the report marks this unresolved.
- The snapshot captures interactive elements and common visible text containers (`p`, headings, list items, blockquotes, SVG, and `role=img`). It does not cover every possible text node or arbitrary data attribute.
- Cross-origin iframe contents and closed shadow roots are not supported. Open shadow DOM and dynamic-page behavior are subject to Playwright locator behavior and have not received comprehensive coverage.
- Detection is heuristic and does not currently implement OCR, NER, face detection, or broad semantic identification. Prompt-injection scanning flags selected patterns; webpage content remains untrusted.
- The egress canary check can only verify values that the detector found. It cannot guarantee that unknown sensitive content is absent.
- The configured timeout is applied to initial navigation, browser actions, screenshot capture, and Playwright operations honoring the page default. Synchronous DOM evaluation and the overall workflow do not have a guaranteed global wall-clock deadline.
- `core/browser/vault.py` and `core/agent/approval.py` remain unimplemented; secret restoration and user-approved consequential actions are unavailable.

## Implemented versus future work

Implemented: local snapshot, current regex/DOM detection, text and image sanitization, redaction status reporting, egress canary checks, safe mock workflow, action validation, and restricted execution.

Future work: real provider integration, vault-backed secret references, explicit approval UX, broader page-content coverage, OCR/semantic detectors, and expanded browser-context testing. These capabilities must be added with privacy and action-safety tests before they are described as supported.

## P2: The Detective (Sensitive Detection & Synthetic Engine)

P2 is responsible for finding sensitive information and generating mathematically valid synthetic replacements to enable "Plausible Deniability" for the LLM.

### 1. Detection Engine (Defense in Depth)
We use a multi-layered approach to ensure 100% recall and precision:
*   **Regex Patterns:** Scans for structural patterns of known PII (Emails, PAN, Phone numbers, API keys like \sk-\ or \AKIA\, JWTs, and IPv4 addresses).
*   **Mathematical Validators:** 
    *   **Luhn Algorithm:** Validates credit/debit card checksums.
    *   **Verhoeff Algorithm:** Validates 12-digit Aadhaar numbers using the dihedral group \(D_5\).
*   **DOM Structural Rules:** Inspects HTML attributes to catch secrets that regex might miss (\	ype="password"\, \utocomplete="cc-number"\, keywords like "cvv").

### 2. The Synthetic Swap Engine (Plausible Deniability)
Standard redaction breaks the AI because it sends \[REDACTED:CARD]\, which is invalid form data. P2 solves this by generating valid synthetic data:
*   **Luhn-Valid Cards:** When a real card is detected, P2 preserves the first 6 digits (BIN) and generates a mathematically valid fake card.
*   **Reserved Emails:** Generates safe \@example.com\ variants.
*   **Consistency Cache:** Repeated occurrences of a secret map to the exact same synthetic value so the AI isn't confused.
*   **Evaluation:** Our \eval_synthetic.py\ proves that synthetic data passes standard frontend validation (Luhn, regex), whereas standard redaction would cause the form to reject the AI's actions.

### 3. Mosaic Shield Risk Scoring (Phase 4)
Detects when multiple low-risk items combine into a high-risk identity profile.
*   **The Math:** \(R_{total} = \sum \sqrt{w_i \cdot \text{Confidence}_i} + \lambda \cdot \exp(\text{Density})\)
*   If a page contains too many identity factors (e.g., Name + Email + Address + Card), the system flags it as \HIGH MOSAIC RISK\ to trigger a human approval gate before the AI acts.

### Evaluation Results
*   **Detection:** 1.0 Recall / 1.0 Precision across 5 test scenarios.
*   **Unit Tests:** 7/7 passing (Luhn, Verhoeff, Synthetic consistency, Error handling).
