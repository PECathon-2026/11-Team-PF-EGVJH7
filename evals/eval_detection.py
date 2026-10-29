import json
import os
import re
from playwright.sync_api import sync_playwright
from contracts.models import PageSnapshot, Element, BBox
from core.detect import detect

# We use a local snapshot function so we don't depend on P1's code being perfect yet
def local_take_snapshot(page):
    elements = page.evaluate('''() => {
        let els = [];
        let nodes = document.querySelectorAll('input, textarea, button, span, p, label');
        let id_counter = 1;
        for (let node of nodes) {
            if (node.offsetWidth === 0 && node.offsetHeight === 0) continue;
            let rect = node.getBoundingClientRect();
            let el = {
                id: 'e' + id_counter++,
                tag: node.tagName.toLowerCase(),
                type: node.type || null,
                name: node.name || null,
                label: node.labels && node.labels.length > 0 ? node.labels[0].innerText : null,
                text: node.innerText || '',
                value: node.value || '',
                bbox: {x: rect.x, y: rect.y, w: rect.width, h: rect.height},
                attrs: {}
            };
            for (let attr of node.attributes) {
                if (attr.name !== 'id') el.attrs[attr.name] = attr.value;
            }
            // Use CSS selector as the stable ID for evaluation mapping
            el.attrs['css_selector'] = node.id ? '#' + node.id : null;
            els.push(el);
        }
        return els;
    }''')
    
    elements = []
    for e in page.evaluate('''() => {
        let els = [];
        let nodes = document.querySelectorAll('input, textarea, button, span, p, label');
        for (let node of nodes) {
            if (node.offsetWidth === 0 && node.offsetHeight === 0) continue;
            let rect = node.getBoundingClientRect();
            let el = {
                tag: node.tagName.toLowerCase(),
                type: node.type || null,
                name: node.name || null,
                label: node.labels && node.labels.length > 0 ? node.labels[0].innerText : null,
                text: node.innerText || '',
                value: node.value || '',
                bbox: {x: rect.x, y: rect.y, w: rect.width, h: rect.height},
                attrs: {}
            };
            for (let attr of node.attributes) {
                el.attrs[attr.name] = attr.value;
            }
            el.attrs['css_selector'] = node.id ? '#' + node.id : null;
            els.push(el);
        }
        return els;
    }'''):
        # Need to assign element IDs that match our Detection model (e1, e2...)
        elements.append(Element(
            id="temp", tag=e["tag"], type=e["type"], name=e["name"], label=e["label"],
            text=e["text"], value=e["value"], bbox=BBox(**e["bbox"]), attrs=e["attrs"]
        ))
    
    # Assign stable IDs based on CSS selector so we can match ground truth later
    for i, el in enumerate(elements):
        el.id = f"e{i+1}"

    return PageSnapshot(url=page.url, title=page.title(), screenshot=b"", elements=elements)


def evaluate_page(page_name):
    pages_dir = "testlab/pages"
    gt_dir = "testlab/ground_truth"
    
    gt_path = os.path.join(gt_dir, f"{page_name}.json")
    if not os.path.exists(gt_path):
        return None
        
    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    url = f"http://localhost:8000/{page_name}.html"
    
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url)
        
        snap = local_take_snapshot(page)
        dets = detect(snap)
        browser.close()

    # Map element IDs back to CSS selectors for comparison
    el_to_css = {el.id: el.attrs.get('css_selector') for el in snap.elements}

    tp = 0
    fp = 0
    fn = 0
    
    # Check for True Positives and False Negatives
    matched_gt = set()
    for gt in ground_truth:
        found = False
        for d in dets:
            if el_to_css.get(d.element_id) == gt["element_id_selector"]:
                # Check if the type matches
                if d.type == gt["type"]:
                    found = True
                    break
        if found:
            tp += 1
            matched_gt.add(gt["element_id_selector"])
        else:
            fn += 1

    # Check for False Positives (detections that don't match any ground truth)
    for d in dets:
        css = el_to_css.get(d.element_id)
        if css not in matched_gt:
            fp += 1

    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0

    return {
        "page": page_name,
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "tp": tp, "fp": fp, "fn": fn
    }

if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    pages = ["checkout", "login", "dev", "support", "video"]
    results = []
    
    print("Starting Evaluation... (Make sure testlab/serve.py is running!)")
    for page in pages:
        res = evaluate_page(page)
        if res:
            results.append(res)
            print(f"{page.capitalize()}: Recall={res['recall']}, Precision={res['precision']} (TP:{res['tp']} FP:{res['fp']} FN:{res['fn']})")

    with open("results/detection.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nEvaluation complete. Results saved to results/detection.json")
