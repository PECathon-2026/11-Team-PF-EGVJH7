"""Run accuracy and processing-performance evaluations on local fixtures.

Start the fixture server first with ``python -m testlab.serve``.
"""

import argparse
import json
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

from contracts.models import BBox, Element, PageSnapshot
from core.detect import detect
from core.sanitize import sanitize
from evals.performance import (
    PeakRssSampler,
    elapsed_ms,
    new_scenario_record,
    resource_snapshot,
    write_performance_results,
)

ROOT = Path(__file__).resolve().parents[1]
PAGES = ("checkout", "login", "dev", "support", "video")
EVALUATION_TIMEOUT_MS = 30000


class FixtureResponseError(RuntimeError):
    def __init__(self, status):
        super().__init__("Fixture page did not return a successful HTTP response.")
        self.status = status


def local_take_snapshot(page):
    """Use the evaluation's selector-aware snapshot and capture its viewport."""
    elements = []
    for item in page.evaluate("""() => {
        const nodes = document.querySelectorAll('input, textarea, button, [id]');
        return [...nodes].filter(node => !(node.offsetWidth === 0 && node.offsetHeight === 0))
            .map(node => {
                const rect = node.getBoundingClientRect();
                const attrs = Object.fromEntries([...node.attributes].map(a => [a.name, a.value]));
                if (node.id) attrs.css_selector = '#' + node.id;
                return {
                    tag: node.tagName.toLowerCase(), type: node.type || null,
                    name: node.name || null,
                    label: node.labels && node.labels.length ? node.labels[0].innerText : null,
                    text: node.innerText || '', value: node.value || '',
                    bbox: {x: rect.x, y: rect.y, w: rect.width, h: rect.height}, attrs
                };
            });
    }"""):
        attrs = {key: str(value) for key, value in item["attrs"].items() if value is not None}
        elements.append(Element(
            id=f"e{len(elements) + 1}", tag=item["tag"], type=item["type"],
            name=item["name"], label=item["label"], text=item["text"],
            value=item["value"], bbox=BBox(**item["bbox"]), attrs=attrs,
        ))

    viewport = page.evaluate("""() => ({width: window.innerWidth, height: window.innerHeight,
        dpr: window.devicePixelRatio || 1})""")
    screenshot = page.screenshot(full_page=False, timeout=EVALUATION_TIMEOUT_MS)
    return PageSnapshot(
        url=page.url,
        title=page.title(),
        screenshot=screenshot,
        elements=elements,
        viewport_size=(viewport["width"], viewport["height"]),
        device_pixel_ratio=viewport["dpr"],
    )


def calculate_accuracy(ground_truth, snapshot, detections):
    """Retain the existing selector/type TP, FP, FN calculation."""
    element_to_css = {
        element.id: element.attrs.get("css_selector")
        for element in snapshot.elements
    }
    tp = fp = fn = 0
    matched_ground_truth = set()
    for expected in ground_truth:
        found = any(
            element_to_css.get(detection.element_id) == expected["element_id_selector"]
            and detection.type == expected["type"]
            for detection in detections
        )
        if found:
            tp += 1
            matched_ground_truth.add(expected["element_id_selector"])
        else:
            fn += 1
    for detection in detections:
        css = element_to_css.get(detection.element_id)
        if css not in matched_ground_truth:
            fp += 1
    return {
        "recall": round(tp / (tp + fn), 3) if tp + fn else 1.0,
        "precision": round(tp / (tp + fp), 3) if tp + fp else 1.0,
        "tp": tp, "fp": fp, "fn": fn,
    }


def evaluate_page(page_name, base_url="http://localhost:8000", ground_truth_dir=None):
    """Evaluate one local scenario and record failed attempts with partial timings."""
    ground_truth_dir = Path(ground_truth_dir or ROOT / "testlab" / "ground_truth")
    gt_path = ground_truth_dir / f"{page_name}.json"
    if not gt_path.exists():
        return None
    with gt_path.open("r", encoding="utf-8-sig") as source:
        ground_truth = json.load(source)

    record = new_scenario_record(page_name)
    accuracy = {"recall": None, "precision": None, "tp": 0, "fp": 0, "fn": 0}
    baseline = resource_snapshot().get("process_rss_mib")
    record["rss_mib"]["before"] = baseline
    sampler = PeakRssSampler().start()
    end_to_end_start = time.perf_counter()
    manager = browser = None
    stage = "browser_startup"
    browser_start = time.perf_counter()

    try:
        playwright = sync_playwright()
        manager = playwright.start()
        browser = manager.chromium.launch()
        record["latency_ms"]["browser_startup"] = elapsed_ms(browser_start, time.perf_counter())

        page = browser.new_page()
        stage = "page_load"
        start = time.perf_counter()
        try:
            response = page.goto(
                f"{base_url.rstrip('/')}/{page_name}.html",
                wait_until="domcontentloaded",
                timeout=EVALUATION_TIMEOUT_MS,
            )
            if response is None or not response.ok:
                raise FixtureResponseError(None if response is None else response.status)
        finally:
            record["latency_ms"]["page_load"] = elapsed_ms(start, time.perf_counter())

        stage = "snapshot"
        start = time.perf_counter()
        try:
            snapshot = local_take_snapshot(page)
        finally:
            record["latency_ms"]["snapshot"] = elapsed_ms(start, time.perf_counter())
        record["elements_processed"] = len(snapshot.elements)

        stage = "detection"
        start = time.perf_counter()
        try:
            detections = detect(snapshot)
        finally:
            record["latency_ms"]["detection"] = elapsed_ms(start, time.perf_counter())
        record["sensitive_detections"] = len(detections)
        accuracy = calculate_accuracy(ground_truth, snapshot, detections)

        stage = "sanitization"
        start = time.perf_counter()
        try:
            sanitized = sanitize(snapshot, detections)
        finally:
            record["latency_ms"]["sanitization"] = elapsed_ms(start, time.perf_counter())
        redaction_summary = next((
            row for row in sanitized.report
            if isinstance(row, dict) and row.get("kind") == "image_redaction_summary"
        ), None)
        record["redactions"] = sum(
            1 for row in sanitized.report
            if (hasattr(row, "secret_type") or
                (isinstance(row, dict) and row.get("status") == "redacted"))
        )
        if redaction_summary is None or redaction_summary.get("status") != "complete":
            record["error"] = {"stage": "sanitization", "type": "UnresolvedImageRedactions"}
        else:
            record["success"] = True

    except Exception as exc:
        record["error"] = {"stage": stage, "type": type(exc).__name__}
        if isinstance(exc, FixtureResponseError):
            record["error"]["http_status"] = exc.status
        if stage == "browser_startup" and record["latency_ms"]["browser_startup"] is None:
            record["latency_ms"]["browser_startup"] = elapsed_ms(browser_start, time.perf_counter())
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                if record["error"] is None:
                    record["error"] = {"stage": "browser_cleanup", "type": "BrowserCleanupError"}
                    record["success"] = False
        if manager is not None:
            try:
                manager.stop()
            except Exception:
                if record["error"] is None:
                    record["error"] = {"stage": "browser_cleanup", "type": "PlaywrightCleanupError"}
                    record["success"] = False
        detection_ms = record["latency_ms"]["detection"]
        sanitization_ms = record["latency_ms"]["sanitization"]
        if detection_ms is not None and sanitization_ms is not None:
            record["latency_ms"]["processing"] = detection_ms + sanitization_ms
        record["latency_ms"]["end_to_end"] = elapsed_ms(end_to_end_start, time.perf_counter())
        record["rss_mib"]["peak_sampled"] = sampler.stop()
        after = resource_snapshot().get("process_rss_mib")
        record["rss_mib"]["after"] = after
        if baseline is not None and after is not None:
            record["rss_mib"]["change"] = after - baseline

    return {
        "accuracy": {"page": page_name, **accuracy, "success": record["success"]},
        "performance": record,
    }


def run_evaluation(base_url="http://localhost:8000", results_dir=None):
    """Run all available synthetic pages and save accuracy and performance separately."""
    results_dir = Path(results_dir or ROOT / "results")
    accuracy_results = []
    performance_results = []
    print("Starting local detection + sanitization evaluation (testlab server required).")
    for page_name in PAGES:
        result = evaluate_page(page_name, base_url=base_url)
        if result is None:
            continue
        accuracy_results.append(result["accuracy"])
        performance_results.append(result["performance"])
        metrics = result["performance"]
        print(
            f"{page_name.capitalize()}: recall={result['accuracy']['recall']}, "
            f"precision={result['accuracy']['precision']}, "
            f"detections={metrics['sensitive_detections']}, "
            f"processing_ms={metrics['latency_ms']['processing']}, "
            f"success={metrics['success']}"
        )

    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "detection.json").write_text(
        json.dumps(accuracy_results, indent=2) + "\n", encoding="utf-8"
    )
    metrics_path, summary_path = write_performance_results(performance_results, results_dir)
    print(f"Detection results saved to {results_dir / 'detection.json'}")
    print(f"Performance details saved to {metrics_path}")
    print(f"Performance summary saved to {summary_path}")
    return accuracy_results, performance_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate detection and sanitization on synthetic pages")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Base URL served by testlab.serve")
    args = parser.parse_args()
    run_evaluation(base_url=args.base_url)
