import time
from playwright.sync_api import sync_playwright
from contracts.models import Action
from core.browser import take_snapshot, execute_action, ExecutionError
from core.detect import detect
from core.detect.synthetic import get_synthetic_value
from core.sanitize import sanitize

def run_demo():
    print("========================================")
    print("🚀 STARTING PRIVACYLENS END-TO-END DEMO")
    print("========================================\n")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False) 
        page = browser.new_page()
        page.goto("http://localhost:8000/checkout.html")
        
        # 1. P1 Snapshot
        print("[1] P1: Taking snapshot...")
        snap = take_snapshot(page)
        
        # 2. P2 Detect
        print("[2] P2: Detecting secrets...")
        dets = detect(snap)
        print(f"    -> Found {len(dets)} sensitive items.")
        
        # 3. P3 Sanitize (With our synthetic hack)
        print("[3] P3: Sanitizing view...")
        result = sanitize(snap, dets)
        view = result[0] if isinstance(result, tuple) else result
        
        private_map = {}
        for el in view.elements:
            if "[REDACTED:" in el.value:
                original_det = next((d for d in dets if d.element_id == el.id), None)
                if original_det:
                    det_type = original_det.type
                    real_value = next((s.value for s in snap.elements if s.id == el.id), None)
                    if real_value:
                        synth_val = get_synthetic_value(det_type, real_value)
                        el.value = synth_val
                        private_map[synth_val] = real_value
        
        print("\n--- WHAT THE AI SEES (Sanitized) ---")
        for el in view.elements:
            if el.value:
                print(f"    {el.name}: {el.value}")
                
        # 4. P4 Simulated Smart LLM
        print("\n[4] P4: AI Agent is analyzing the page...")
        print("    (Waiting 20 seconds for AI reasoning loop...)")
        time.sleep(20) # Wait 20 seconds to simulate AI thinking
        
        print("\n[5] P4: AI decided to fill out the form and checkout.")
        
        # Find elements
        email_el = next((e for e in view.elements if e.name == "email"), None)
        card_el = next((e for e in view.elements if e.name == "card"), None)
        cvv_el = next((e for e in view.elements if e.name == "cvv"), None)
        pay_btn = next((e for e in view.elements if e.name == "pay" or e.text == "Pay Now"), None)

        # 6. P1 Execute with Secret Swapping
        print("\n[6] P1: Executing AI actions & swapping secrets locally...")
        
        if email_el:
            action_email = Action(type="type", element_id=email_el.id, text=email_el.value)
            action_email.text = private_map[action_email.text]
            execute_action(page, snap, action_email)
            print(f"    🔄 Typed real email: {action_email.text}")
            
        if card_el:
            action_card = Action(type="type", element_id=card_el.id, text=card_el.value)
            action_card.text = private_map[action_card.text]
            execute_action(page, snap, action_card)
            print(f"    🔄 Typed real card: {action_card.text}")
            
        if cvv_el:
            action_cvv = Action(type="type", element_id=cvv_el.id, text=cvv_el.value)
            action_cvv.text = private_map[action_cvv.text]
            execute_action(page, snap, action_cvv)
            print(f"    🔄 Typed real CVV: {action_cvv.text}")
        
        # 7. AI tries to click Pay
        print("\n[7] P4: AI decides to click 'Pay Now'...")
        pay_action = Action(type="click", element_id=pay_btn.id)
        
        print("    [8] P1: Executing Pay action...")
        try:
            execute_action(page, snap, pay_action)
            print("    ✅ Execution complete!")
        except ExecutionError as e:
            # THIS IS THE SECURITY WIN
            print(f"    🛡️ [SECURITY BLOCK]: {e}")
            print("       Human approval is required before clicking consequential buttons.")
            
        print("\n========================================")
        print("🏁 DEMO COMPLETE - LOOK AT THE BROWSER!")
        print("========================================")
        
        page.wait_for_timeout(10000) 
        browser.close()

if __name__ == '__main__':
    run_demo()
