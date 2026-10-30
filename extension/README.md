# PrivacyLens browser extension

**Your Privacy Firewall for Autonomous AI.** An AI browser agent for Chrome and
Edge that never sees your real data: detection, synthetic substitution,
prompt-injection quarantine and a fail-closed egress firewall all run inside
the extension, and the AI only ever receives a sanitized copy of the page.

## Install (about 1 minute)

1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and select this `extension/` folder.
3. Pin PrivacyLens and click its icon: the side panel opens.
4. On any http(s) page, click **Allow on this site** (access is granted per site, at runtime).

Requires Chrome/Edge 116+. Firefox is not supported (no side-panel API).

## Screens

| Screen | What it does | Backed by |
| --- | --- | --- |
| **Overview** | Firewall on/off switch, current site and monitoring status, live counts for this page, agent connection and privacy mode, mosaic risk, activity feed | `protectionBlocker`, `scanPage`, `riskBreakdown`; switch also drives the toolbar badge via the service worker |
| **Scanner** | *Scan Current Page*; per field, **what you see** (secrets masked in context) next to **what the AI sees**; detection method, action, format checks; the exact AI payload | `scanPage` → `sanitizeSnapshot` |
| **AI-Eye** | Overlay on the real page (`PROTECTED · CARD`, `QUARANTINED · PROMPT INJECTION`, `CENSORED · VIDEO`), **video privacy shield**, legend, live monitoring indicator | content script `overlay` / `shield` / `ping` |
| **Agent** | Natural-language tasks, Gemini vs offline mode banner, OBSERVE → SANITIZE → REASON → VALIDATE → APPROVE → EXECUTE stepper, sanitized context, proposed actions | `runAgent`, `geminiAgent`, `mockAgent` |
| **Approvals** | Pending request (also as a modal), risk class, data that would be used (masked), Approve once / Deny, history | `classifyRisk`, single-use grants in the content script |
| **Threats** | All PS-004 categories with counts and severity, detected threats table, prompt-injection section (visible/hidden, why, reached the AI?) | `taxonomy.js`, sanitizer injection findings |
| **Validation** | **Run firewall self-test** with per-check evidence; status of every protection mechanism, including the Chrome-enforced network allowlist | `firewallSelfTest`, manifest CSP |
| **Ledger** | SHA-256 hash-chained audit trail, **Verify hash chain**, **Export privacy receipt**, filters by event and date, verified/unverified marks | `AuditLedger` |
| **Test Lab** | The five PS-004 scenarios against `testlab/pages`: expected vs actual, pass/fail/not-supported per check, evidence | `scenarios.js` + the real pipeline |
| **Settings** | Protection toggles, Gemini key/model/connection test, local-only mode, per-site access and revocation, never-send list, strict redaction, retention, theme | `chrome.storage`, `chrome.permissions` |

## Filling forms (sign in, register, checkout)

The agent fills forms from **Settings → My details**. Leave a field empty and,
with *Use a synthetic test identity* on (the default), a fake value is used
instead, so the agent works out of the box on test sites.

| Field | What the AI sees | Typed on the page | Approval |
| --- | --- | --- | --- |
| Name, email, phone, address | synthetic stand-in | your real value (swapped in locally) | no |
| Card number | synthetic Luhn-valid card | your real card | **yes** |
| Card expiry | as is (not sensitive alone) | as is | no |
| Username | `[SECRET]`, referenced as `secret_ref` | your real value | no |
| Password, CVV | `[SECRET]`, referenced as `secret_ref` | your real value | **yes** |

Form submissions (e.g. *Sign in*, *Create account*) also need **Approve once**.
Password fields accept nothing but the saved password, and the page-side
executor refuses to type into one without a valid grant. Details are kept in
`chrome.storage.session` (memory only) and never appear in the UI unmasked,
in the ledger, or in anything sent to the AI.

Try it: `python testlab/serve.py`, open <http://127.0.0.1:8000/signin.html> or
`register.html`, and run *Sign in to my account* / *Create an account*.

## Video calls

Two protections, for two different audiences:

- **The AI.** PrivacyLens sends text only: video frames and screenshots are
  never captured or sent. Participant names announced by a label (`Name:`,
  `Host:`, `Speaker:`, `Participant:`, `From:` …) or held in a name field are
  detected and replaced with synthetic names, like emails and phones.
- **Your screen.** AI-Eye → *Video privacy shield* blurs every `<video>` and
  `<canvas>` feed and every detected personal detail (names, emails, phones,
  cards…) directly on the page, for screen sharing, recordings and
  shoulder-surfing. Tiles that appear later (people joining) are blurred as
  they appear; switching the shield off restores the page exactly.

Not done: per-face detection (the shield blurs whole frames), and names that
appear in free text without a label.

## Running the five PS-004 scenarios

1. From the repository root: `python testlab/serve.py` (serves `testlab/pages` on port 8000).
2. Open the **Test Lab** screen and click **Run all five scenarios** (or one **Run test**).
   The first run asks for access to `127.0.0.1`.

Scenarios always use the secure default settings. Current, verified results:

| # | Scenario | Result | What is checked |
| --- | --- | --- | --- |
| 1 | E-commerce checkout | PASS (13 checks) | card/CVV/email/address replaced (card Luhn-valid); real agent run asks approval for *Pay Now* (critical); page-side executor refuses Pay without a grant; payload with the real card blocked |
| 2 | Authentication | PASS (10) | password and OTP redacted, email replaced, password typed into the task redacted |
| 3 | Customer support | PASS (12) | emails and Indian mobiles (`+91 9876543210`, `+91 98765 43210`, `9876543210`) replaced; visible and hidden prompt injections never reach the AI |
| 4 | Video conferencing | PARTIAL (all checks pass, 1 not supported) | participant name and email replaced for the AI; shield blurs the video feed, name and email on the page (checked via computed styles); **per-face detection is not implemented**, reported as "not supported" |
| 5 | Developer settings | PASS (14) | OpenAI/AWS/GitHub keys, JWT and IP redacted; real-key payload blocked; unregistered key caught by the second-opinion scan |

## Gemini setup

Settings → AI configuration: choose **Gemini**, paste an API key, keep or change
the model (default `gemini-2.5-flash`), click **Test connection** (reads model
metadata only, sends no page data). The key lives in `chrome.storage.session`:
memory only, never written to disk, cleared when the browser closes.
**Local-only mode** blocks every cloud call regardless of the agent setting.

## Architecture

```
side panel (extension page, ES modules)            web page
┌──────────────────────────────────────────┐      ┌─────────────────────────┐
│ views/*  ─▶ controller.js ─▶ core/*      │ msg  │ content/content.js      │
│  (display-safe store: masked/synthetic)  │◀────▶│ snapshot · executor     │
│ core: detect → sanitize → egress → agent │      │ (own approval check)    │
│       policy → approval → execute        │      │ AI-Eye overlay          │
└───────────────┬──────────────────────────┘      └─────────────────────────┘
                │ only network path: guardedFetch, CSP connect-src = Gemini
                ▼
     generativelanguage.googleapis.com   (Gemini mode only)
service worker: opens the panel, mirrors the firewall state on the toolbar badge
```

- **Python ↔ JavaScript.** There is no runtime connection: the extension is
  self-contained. The Python package (`core/`) is the reference implementation;
  `tests/test_extension_parity.py` proves the JS detectors return the *same
  spans* as Python on the testlab pages plus 600 fuzzed strings, and that the
  JS mosaic-risk score equals Python's `calculate_mosaic_risk`.
- **Trust boundaries.** Real values exist only in the page and in the panel's
  memory (`SyntheticVault`, scan inventory). The UI store, ledger, activity feed
  and every screen hold masked or synthetic values only.

## Security assumptions

- The browser, the extension's own code and the user's machine are trusted; the
  web page and the AI model are not.
- Turning protection off never sends raw data: it stops sending altogether.
  Turning off injection quarantine or invisible-text filtering only reduces
  prompt-injection protection; secrets are still replaced.
- Approvals are single-use, expire after 30 s, are bound to one element, one
  action type and one snapshot, and are enforced again by the page-side
  executor, which the side panel cannot bypass.

## Known limitations

- Text only: no screenshots are sent. The video shield blurs whole frames on
  the page; there is no per-face detection.
- Names are only detected where a label or field says so (no NER model).
- Only the top-level frame is covered; card fields inside third-party iframes
  (e.g. hosted payment forms) are not seen.
- Gemini mode sends a `responseSchema` so replies have the exact action shape,
  and its request building, error handling and egress check are unit-tested
  with a mocked API. It has **not yet been run against the live API** (no key
  was available): do one real run with your key before the demo.
- The offline agent is a rule-based planner (fill empty fields from My details,
  then click the control matching the task, following links across pages). It
  only understands labelled form fields; open-ended tasks such as "find a product
  under ₹2,000" need Gemini.
- The ledger is per session (memory only); there is no persistent log by design.

Multi-page tasks work: the content script is re-attached after every
navigation (verified end to end: catalog → checkout → approval).

## Tests

```sh
cd extension && npm test                          # 57 unit tests (Node ≥ 20)
python -m pytest tests/test_extension_parity.py   # JS == Python detectors and risk score
python -m pytest tests/test_extension_e2e.py      # real Chromium + real extension, 19 tests
python -m pytest                                  # everything (Python + parity + E2E)
```

## Layout

| Path | Role |
| --- | --- |
| `src/core/patterns.js`, `detect.js` | P2: regex + Luhn/Verhoeff, Indian mobiles, structural hints, mosaic risk |
| `src/core/synthetic.js` | Format-preserving synthetic values (independent BIN, kept country code) + vault |
| `src/core/sanitize.js` | P3: AI view, invisible-text drop, injection quarantine, task-credential redaction |
| `src/core/egress.js` | P3: fail-closed egress firewall + second-opinion re-scan |
| `src/core/policy.js` | P4: strict action parsing, navigation policy, approval rules, risk classes |
| `src/core/audit.js` | SHA-256 hash-chained ledger |
| `src/core/orchestrator.js` | `scanPage`, `runAgent`, honeytokens, firewall self-test |
| `src/core/scenarios.js`, `taxonomy.js` | PS-004 scenarios and evaluator; display metadata |
| `src/content/content.js` | P1: snapshot, executor with independent grant checks, overlay |
| `src/sidepanel/` | UI: `controller.js`, `store.js`, `ui.js`, `views/*` |
| `src/background/service-worker.js` | Panel wiring, firewall badge |
