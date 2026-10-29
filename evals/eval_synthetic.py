from core.detect.synthetic import get_synthetic_value
from core.detect.validators import luhn_ok
import re

def run_evaluation():
    print("=== PHASE 3: GENERATOR EVALUATION ===")
    print("Comparing standard REDACTION vs. SYNTHETIC SWAP\n")
    print("Goal: Check generated synthetic values against local format validators.\n")

    test_cases = [
        ("CARD", "4111 1111 1111 1111"),
        ("EMAIL", "john.doe@company.com"),
        ("PHONE", "+91 98765 43210")
    ]

    print(f"{'Type':<8} | {'Synthetic Input':<22} | {'Redacted':<18} | {'Synthetic Output':<26} | {'Form Valid?'}")
    print("-" * 115)

    for det_type, real_val in test_cases:
        # 1. The old Phase 1 method
        redacted = f"[REDACTED:{det_type}]"
        
        # 2. The new Phase 2 method
        synth_val = get_synthetic_value(det_type, real_val)
        
        # 3. Validation Check (Simulating an HTML5 form submission)
        is_valid = False
        if det_type == "CARD":
            clean_synth = re.sub(r"[ -]", "", synth_val)
            is_valid = luhn_ok(clean_synth)
        elif det_type == "EMAIL":
            is_valid = bool(re.match(r"^[\w\.-]+@example\.com$", synth_val))
        elif det_type == "PHONE":
            is_valid = len(re.sub(r"\D", "", synth_val)) == 12 # e.g., 919876543210

        valid_str = "PASS" if is_valid else "FAIL"
        
        # Print the comparison row
        print(f"{det_type:<8} | {real_val:<22} | {redacted:<18} | {synth_val:<26} | {valid_str}")

    print("\n--- CONCLUSION ---")
    print("This script checks synthetic format validity only; it does not run a browser, agent, or vault integration.")

if __name__ == '__main__':
    run_evaluation()
