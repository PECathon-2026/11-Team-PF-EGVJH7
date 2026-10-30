# PrivacyLens

A privacy-preserving AI browser agent (PECathon 2026, PS-004). Sensitive data
on a web page is detected (patterns + Luhn/Verhoeff validation + page
structure), replaced with synthetic values or placeholders before any AI sees
it, and every outgoing request passes a fail-closed egress firewall. Risky
actions such as payments need explicit human approval.

## Browser extension

The complete product is a Chrome/Edge side-panel extension in
[`extension/`](extension/README.md): live privacy scanner, AI-Eye page
overlay, agent with an OBSERVE → SANITIZE → REASON → VALIDATE → APPROVE →
EXECUTE lifecycle, approval center, threat and validation centers, a
hash-chained ledger and a Test Lab for the five PS-004 scenarios. Install it
with **Load unpacked**; see [extension/README.md](extension/README.md).

## Tests

```sh
pip install -r requirements.txt && python -m playwright install chromium
python -m pytest            # Python suite + JS/Python parity + extension E2E
cd extension && npm test    # extension unit tests (Node >= 20)
```

## Performance Evaluation & Benchmarks

PrivacyLens includes an evaluation pipeline for measuring detection latency, sanitization latency, end-to-end processing time, and Python process memory usage. Detection precision and recall are evaluated against synthetic ground-truth scenarios.

### Benchmark Results

The following results were recorded during a local evaluation of five synthetic scenarios.

| Metric | Result |
|---|---:|
| Evaluation scenarios | 5 |
| Detection precision | 1.00 (100%) |
| Detection recall | 1.00 (100%) |
| Mean detection latency | 1.58 ms |
| Mean sanitization latency | 48.49 ms |
| Mean combined processing latency | 50.07 ms |
| Median combined processing latency | 39.07 ms |
| Maximum combined processing latency | 91.54 ms |
| Mean end-to-end latency | 1,081.23 ms |
| Maximum end-to-end latency | 1,259.16 ms |
| Mean Python process RSS after scenarios | 44.81 MiB |
| Maximum Python process RSS after scenarios | 45.79 MiB |
| Maximum sampled Python process RSS | 52.35 MiB |

### Methodology and Limitations

- These results represent five local synthetic scenarios, not arbitrary websites or production workloads.
- Precision and recall reflect performance against the synthetic ground truth only.
- End-to-end latency includes overhead beyond detection and sanitization, including browser interaction and HTTP communication.
- Python process RSS excludes the separate Chromium browser process.
- Sampled memory measurements may miss short-lived memory spikes.
- A 95th-percentile latency figure is omitted because five scenarios are insufficient for a meaningful estimate.

### Reproducing the Evaluation

Install the project dependencies and Playwright Chromium browser:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
```

Then start the fixture server and run the evaluation:

```powershell
python testlab/serve.py
python -m evals.eval_detection --base-url http://127.0.0.1:8000
```
