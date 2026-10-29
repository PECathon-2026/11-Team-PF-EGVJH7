# 11-Team-PF-EGVJH7
## P2: The Detective (Sensitive Information Detection)

Our detection engine uses a **Defense-in-Depth** approach to ensure high recall without sacrificing precision. It combines four distinct methods:

1. **Regex Patterns:** We scan for structural patterns of known PII (Emails, PAN, Phone numbers, API keys like \sk-\ or \AKIA\, JWTs, and IPv4 addresses).
2. **Mathematical Validators:** To avoid false positives on random numbers, we use strict algorithmic validation:
   - **Luhn Algorithm:** Used for credit/debit cards (13–19 digits). Validates the checksum using modular arithmetic.
   - **Verhoeff Algorithm:** Used for 12-digit Aadhaar numbers. Utilizes the dihedral group D5 to catch all single-digit errors and adjacent transpositions.
3. **DOM Structural Rules:** We inspect HTML attributes to catch secrets that regex might miss. We flag \	ype="password"\, \utocomplete="cc-number"\ or \one-time-code\, and keyword hints in \
ame\/\label\ attributes (e.g., "cvv", "otp", "api_key").
4. **Merge & Deduplication:** Overlapping detections from different sources are merged. The engine prioritizes specific types (e.g., CARD over OTHER) and increases confidence when multiple independent methods flag the same element.

### Evaluation Results (Phase 3 Gate)
We evaluated our detection engine against a synthetic test lab of 5 scenarios (Checkout, Login, Developer Settings, Support Chat, Video Call). 
The evaluation script (\evals/eval_detection.py\) compares our output against ground-truth JSON files using TP, FP, and FN metrics.

| Scenario | Recall | Precision |
| :--- | :--- | :--- |
| **Checkout** | 1.0 (100%) | 1.0 (100%) |
| **Login** | 1.0 (100%) | 1.0 (100%) |
| **Dev Settings** | 1.0 (100%) | 1.0 (100%) |
| **Support Chat**| 1.0 (100%) | 1.0 (100%) |
| **Video Call** | 1.0 (100%) | 1.0 (100%) |

*(Note: The address field in the checkout page is detected via structural keyword matching, and the CVV is flagged as a CARD, ensuring the AI never sees sensitive financial data).*


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
