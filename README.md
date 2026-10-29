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

