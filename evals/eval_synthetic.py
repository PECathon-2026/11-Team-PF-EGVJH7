from core.detect.synthetic import get_synthetic_value
from core.detect.validators import luhn_ok
import re

def run_evaluation():
    print("=== PHASE 3: GENERATOR EVALUATION ===")
    print("Comparing standard REDACTION vs. SYNTHETIC SWAP\n")
    print("Goal: Prove that synthetic data maintains format validity for the AI, while [REDACTED] breaks it.\n")

    test_cases = [
        ("CARD", "4111 1111 1111 1111"),
        ("EMAIL", "john.doe@company.com"),
        ("PHONE", "+91 98765 43210")
    ]

    print(f"{'Type':<8} | {'Original (Real)':<22} | {'Old Redacted':<18} | {'New Synthetic':<26} | {'Form Valid?'}")
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

        valid_str = "✅ PASS" if is_valid else "❌ FAIL"
        
        # Print the comparison row
        print(f"{det_type:<8} | {real_val:<22} | {redacted:<18} | {synth_val:<26} | {valid_str}")

    print("\n--- CONCLUSION ---")
    print("If the AI agent used the 'Old Redacted' data, the website form would reject it (Invalid Card/Email).")
    print("By using P2's 'New Synthetic' data, the AI can successfully interact with the page, while the real data stays safe in the local vault.")

if __name__ == '__main__':
    run_evaluation()
