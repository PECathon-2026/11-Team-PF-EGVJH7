# PrivacyLens

PrivacyLens is a local browser privacy prototype. It snapshots selected page content, detects selected sensitive values, sanitizes DOM fields and screenshot regions, then can provide a restricted sanitized request to a deterministic mock agent. It is a research project, not a complete privacy filter or production browser agent.

## Architecture

- `core/browser/snapshot.py` collects interactive controls and selected visible text, with viewport-relative CSS-pixel boxes and a viewport screenshot.
- `core/detect/` combines regex and DOM-structure heuristics for selected data types.
- `core/sanitize/` replaces detected text spans, scans for selected prompt-injection phrases, redacts screenshot boxes, and reports unresolved image redactions.
- `core/guard/` contains outbound string-canary checks and other prototype policy helpers.
- `core/agent/llm.py` builds a restricted request and returns deterministic mock actions. It does not call an external model.
- `core/agent/validator.py` validates structured actions. `core/browser/executor.py` independently checks targets and enforces execution restrictions.
- `evals/eval_detection.py` evaluates five local HTML fixtures against synthetic ground truth and records detection and sanitization performance. `evals/eval_synthetic.py` separately checks the format validity of generated synthetic replacements; it is not a page-processing benchmark.

## Environment and installation

The source uses Python 3.10+ syntax. The setup commands below are for Windows PowerShell. Playwright supports Chromium automation through its installed browser binary; this repository has only been exercised on Windows in the current development environment. Linux and macOS may work with Playwright but are not verified here.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

Important runtime dependencies are Pydantic, Playwright, PyYAML, Pillow, and psutil. Pytest is used for regression tests. **Minimum resource requirements have not been established**; there is no tested minimum RAM or CPU guarantee. The regression suite and fixture evaluation were exercised on Windows 11 with Python 3.13.7; the benchmark output records 4 logical CPU cores and about 24,265 MiB total system memory on that run. This is one tested host, not a minimum. A recommended setup is 64-bit Python 3.10+ on an OS where Playwright Chromium can launch, with enough available memory for Python, Chromium, and the fixture workload. Every performance output records the actual Python/platform/resource readings for that run.

The mock browser workflow requires no API credentials. Optional workflow settings are `PRIVACYLENS_START_URL`, `PRIVACYLENS_MAX_ACTIONS`, and `PRIVACYLENS_ACTION_TIMEOUT_MS`; see `core/config.py` for validated ranges.

## Evaluation procedure

From the repository root, install the dependencies and Chromium as above. The accuracy evaluation does **not** start its own HTTP server. Start one server for the local fixture pages in a separate PowerShell window:

```powershell
py -3 -m testlab.serve
```

If port 8000 is already serving a different fixture directory, leave that server running and use a second port instead:

```powershell
py -3 -m http.server 8001 --directory testlab/pages
```

Then run `py -3 -m evals.eval_detection --base-url http://localhost:8001`. The evaluator checks HTTP responses and records a non-success response as a failed scenario rather than treating an empty error page as a successful evaluation.

Then, from the repository root, run the existing synthetic-format evaluation, the page detection/sanitization evaluation, and the test suite:

```powershell
py -3 -m evals.eval_synthetic
py -3 -m evals.eval_detection
py -3 -m pytest tests/ -v
```

`evals.eval_detection` runs the existing five scenarios (`checkout`, `login`, `dev`, `support`, `video`) against `testlab/ground_truth/`. It saves the existing accuracy calculations to `results/detection.json`, detailed processing measurements to `results/performance_metrics.json`, and aggregates to `results/performance_summary.json`. It records failed scenarios as failed rows with an error stage and exception type; it does not store exception text or page values in the metrics. The synthetic-format evaluation prints its comparison rows and does not write a performance report.

The detection accuracy values remain separate from performance measurements. The accuracy evaluation measures browser startup (Playwright driver start and Chromium launch), `page.goto` through `domcontentloaded`, snapshot construction and screenshot capture, detection, sanitization, detection-plus-sanitization processing, and end-to-end scenario time. Processing latency excludes browser startup, page loading, snapshot capture, ground-truth file reading, and server startup. End-to-end time starts inside each scenario after Python imports and ground-truth loading, and includes browser startup, page loading, snapshot, detection, sanitization, and browser cleanup. The local fixture HTTP server is a separate process and its startup time is excluded.

RSS is sampled for the evaluator's Python process with psutil; it includes Python and resident dependencies and excludes the separately launched Chromium process. Before/after RSS are point measurements. Peak sampled RSS is an estimate sampled periodically and may miss short-lived spikes. Unavailable readings are represented as JSON `null`, not zero. The system memory and logical core readings are environment metadata, not resource guarantees. Runtime results vary with hardware, OS, Python and browser versions, system load, and fixture workload. Five synthetic scenarios are useful for local comparison and regression checking, not production-grade latency claims or statistically meaningful service-level guarantees. The 95th percentile is reported only when at least 20 scenario measurements exist.

To run the bounded mock browser workflow separately, start the same fixture server and run:

```powershell
py -3 -m core.orchestrator --mock-llm --url http://127.0.0.1:8000/checkout.html --task "Review the local checkout page safely"
```

Real LLM mode is not implemented. There is no provider adapter or verified real-model execution path.

## Threat Model and Security Assumptions

### Security objectives

The intended principle is: **“Compute what is sensitive locally. Reason globally only on sanitized data.”** PrivacyLens aims to detect selected sensitive values locally, sanitize detected DOM text and screenshot regions, check request strings for detected values, validate proposed structured actions, and restrict execution. Detection and sanitization are fallible; the design does not establish that every sensitive value is found or removed.

### Threats addressed and current protection

| Threat scenario | Implemented defense | Protection and remaining limitation |
| --- | --- | --- |
| Accidental exposure of page data to an AI service | The current agent is a deterministic mock with no external provider call. `build_request()` uses sanitized elements, omits raw attributes, input `name` values, and all URL data. The orchestrator checks detected string canaries before calling the agent and blocks if image redaction is incomplete. | This reduces accidental textual exposure for values found by detection. No real-model path is implemented or tested. Canary matching cannot discover unknown sensitive values, and the request includes the sanitized screenshot. |
| Sensitive values in supported DOM fields or screenshots | Detection scans selected text, input value, label, and placeholder fields plus structural hints. Text sanitization replaces matched spans; image sanitization draws opaque boxes and reports skipped/failed geometry. | Coverage is heuristic and the snapshot covers selected nodes only. Input names and arbitrary attributes are omitted from the agent request rather than comprehensively detected. Hidden/offscreen content is not visually represented. |
| Malicious webpage instructions | Sanitization records matches for a small set of prompt-injection patterns. The mock agent does not follow webpage instructions. | The scanner is not a comprehensive prompt-injection defense and does not neutralize all page text. The system prompt module is not connected to a real model request. A future model integration must treat all page content as untrusted and independently defend against instruction injection. |
| Invalid or unauthorized browser actions | Structured action parsing, `validate()`, stale snapshot/target checks, and executor-side restrictions reject unsupported targets and action payloads. Password-field typing, secret references, form submission, and arbitrary script-backed control clicks are blocked. | These are application checks, not a human authorization workflow. No approval mechanism is implemented. A successful validation result is not user approval. |
| Unsafe navigation targets or redirects | The shared navigation policy accepts HTTP(S), rejects embedded credentials and common destructive operation terms in URL paths, fragments, query keys, and values; validation and execution both apply it. | This is a conservative string heuristic, not a destination allowlist or semantic classifier. It does not revalidate the final URL after server/browser redirects, and arbitrary HTTP(S) hosts are not restricted by a domain policy. Consequential behavior hidden behind a neutral URL may not be identified. |
| Sensitive values in logs or outbound requests | Workflow results use generic stage errors and avoid returning detected values; `PrivacyAuditLog` stores decision metadata rather than payloads. The workflow egress string check rejects known detected substrings. | This does not cover every module or unknown values. The lower-level guard result can contain matched originals in its `leaks` field, and some direct executor exceptions can include browser error details. Callers must not log these values, raw snapshots, requests, action payloads, or browser exceptions. |
| Attempts to perform consequential actions without authorization | The executor blocks form submission and obvious sensitive controls; URL operation checks reject common destructive destinations. | Human approval is not implemented, and the click/navigation policy cannot recognize all consequential actions. The project must not be treated as an authorized payment, deletion, account-change, or credential-entry agent. |

### Trust boundaries and assumptions

- **User's local machine:** assumed to be controlled by the user and not compromised. A compromised OS or local process can read browser state, screenshots, process memory, or files outside PrivacyLens's controls.
- **Browser and webpage:** page text, metadata, element values, links, screenshots, redirects, and scripts are untrusted. The browser is relied on to implement Playwright's documented automation behavior, but page behavior can change between capture and action.
- **Local detection and sanitization:** trusted to run the configured code and dependencies, but considered fallible: heuristic misses, unsupported fields, geometry errors, and race conditions remain possible.
- **Agent/model:** the current mock is local and deterministic. Any future external model is an external trust boundary; only its request builder and egress controls would mediate data, and they are not proof of zero disclosure.
- **Browser executor:** trusted as the final action gate, but model-proposed actions and page destinations remain untrusted inputs. Validation alone is not a consent or approval signal.
- **External network destinations:** untrusted. The current application policy constrains schemes and suspicious URL strings but does not implement a domain allowlist or comprehensive redirect policy.

Compromise of the Python runtime, trusted code, installed dependencies, or browser can invalidate these protections. Synthetic evaluation fixtures do not establish behavior against arbitrary sites.

### Out-of-scope threats and known limitations

- Sensitive values missed by heuristic detection, and formats or locations not supported by current detectors.
- Text and controls outside the selected snapshot selectors; hidden content and information outside the viewport screenshot. Screenshot capture is viewport-only.
- OCR/visual recognition: no OCR detector is integrated, so image-only text is not identified. Screenshot redaction depends on detected DOM geometry.
- Browser/OS compromise, malicious browser extensions, compromised local processes, and compromised or malicious Python/browser dependencies.
- Network-layer attacks such as DNS compromise, TLS interception by a hostile trust store, or destination reputation; application URL checks are not a network security boundary.
- Side channels, timing-based inference, and disclosure inferred by a model from surrounding context even when direct values are replaced.
- Denial of service or resource exhaustion caused by excessively complex or adversarial pages. Per-operation timeouts exist, but the full evaluation/workflow has no guaranteed global wall-clock or memory budget.
- Cross-origin iframe and closed-shadow-root content. Open shadow DOM and dynamic page behavior have not been comprehensively tested.

### Approval and secret handling

`core/agent/approval.py` and `core/browser/vault.py` are empty in this repository. Human approval and vault-backed secret storage/restoration are not implemented. Password entry and `secret_ref` execution are rejected by the executor; PrivacyLens does not provide secure credential injection. Policy validation must not be represented as human approval.

### Security guarantees PrivacyLens does not provide

PrivacyLens does not guarantee complete sensitive-data detection, complete sanitization, absence of all information leakage, correct interpretation of every action, human authorization, safe behavior on every site, or protection against compromised local components. A successful run means only that the implemented checks completed for the captured and detected content; it is not proof that a page is free of sensitive information or that every action is safe.

## Development tests

```powershell
py -3 -m pytest tests/ -v
```

The browser tests use local/synthetic data and require the Playwright Chromium installation. Do not use real personal data or credentials in evaluation fixtures.
