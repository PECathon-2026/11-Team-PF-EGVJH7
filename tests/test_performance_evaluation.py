import json
from types import SimpleNamespace

from contracts.models import BBox, Detection, Element, PageSnapshot
from evals import eval_detection
from evals.performance import (
    LATENCY_FIELDS,
    aggregate_scenarios,
    new_scenario_record,
    write_performance_results,
)


class FakeSampler:
    instances = []

    def __init__(self):
        self.peak_rss_mib = 12.0
        self.stopped = False
        self.instances.append(self)

    def start(self):
        return self

    def stop(self):
        self.stopped = True
        return self.peak_rss_mib


class FakePage:
    url = "http://synthetic.invalid/checkout.html"

    def __init__(self, fail_load=False, status=200):
        self.fail_load = fail_load
        self.status = status

    def goto(self, *_args, **_kwargs):
        if self.fail_load:
            raise RuntimeError("synthetic failure")
        return SimpleNamespace(ok=self.status < 400, status=self.status)


class FakeBrowser:
    def __init__(self, page):
        self.page = page

    def new_page(self):
        return self.page

    def close(self):
        pass


class FakeManager:
    def __init__(self, page):
        self.chromium = SimpleNamespace(launch=lambda: FakeBrowser(page))

    def stop(self):
        pass


def _patch_environment(monkeypatch, page):
    monkeypatch.setattr(eval_detection, "sync_playwright", lambda: SimpleNamespace(
        start=lambda: FakeManager(page)
    ))
    monkeypatch.setattr(eval_detection, "PeakRssSampler", FakeSampler)
    monkeypatch.setattr(eval_detection, "resource_snapshot", lambda: {
        "process_rss_mib": 10.0,
    })


def test_successful_scenario_reports_nonnegative_latency_fields(monkeypatch):
    page = FakePage()
    _patch_environment(monkeypatch, page)
    snapshot = PageSnapshot(
        url=page.url, screenshot=b"synthetic", elements=[Element(
            id="e1", tag="input", bbox=BBox(x=1, y=1, w=10, h=10),
            attrs={"css_selector": "#email"},
        )],
    )
    monkeypatch.setattr(eval_detection, "local_take_snapshot", lambda _page: snapshot)
    monkeypatch.setattr(eval_detection, "detect", lambda _snapshot: [
        Detection(type="EMAIL", element_id="e1", field="value", span=(0, 3))
    ])
    monkeypatch.setattr(eval_detection, "sanitize", lambda *_args: SimpleNamespace(report=[{
        "kind": "image_redaction_summary", "status": "complete",
    }]))

    result = eval_detection.evaluate_page("checkout")
    metrics = result["performance"]
    assert metrics["success"] is True
    assert metrics["elements_processed"] == 1
    assert metrics["sensitive_detections"] == 1
    for field in LATENCY_FIELDS:
        assert isinstance(metrics["latency_ms"][field], (int, float))
        assert metrics["latency_ms"][field] >= 0


def test_failed_scenario_keeps_error_and_partial_timings(monkeypatch):
    FakeSampler.instances.clear()
    _patch_environment(monkeypatch, FakePage(fail_load=True))
    result = eval_detection.evaluate_page("checkout")
    metrics = result["performance"]
    assert metrics["success"] is False
    assert metrics["error"] == {"stage": "page_load", "type": "RuntimeError"}
    assert metrics["latency_ms"]["page_load"] >= 0
    assert metrics["latency_ms"]["end_to_end"] >= 0
    assert FakeSampler.instances[-1].stopped is True


def test_http_error_response_is_not_counted_as_scenario_success(monkeypatch):
    _patch_environment(monkeypatch, FakePage(status=404))
    result = eval_detection.evaluate_page("checkout")
    assert result["performance"]["success"] is False
    assert result["performance"]["error"] == {
        "stage": "page_load", "type": "FixtureResponseError", "http_status": 404,
    }


def test_aggregate_empty_and_unavailable_values_do_not_become_zero():
    empty = aggregate_scenarios([])
    assert empty["scenarios_attempted"] == 0
    assert empty["latency_ms"]["processing"]["mean_ms"] is None
    assert empty["rss_mib"]["maximum_sampled_peak"] is None

    row = new_scenario_record("unavailable")
    row["rss_mib"] = {"before": None, "after": None, "change": None, "peak_sampled": None}
    summary = aggregate_scenarios([row])
    assert summary["rss_mib"]["mean_after_scenario"] is None
    assert summary["rss_mib"]["maximum_sampled_peak"] is None


def test_latency_aggregates_include_p95_for_at_least_twenty_samples():
    rows = []
    for value in range(1, 21):
        row = new_scenario_record(str(value))
        row["latency_ms"]["processing"] = float(value)
        rows.append(row)
    stats = aggregate_scenarios(rows)["latency_ms"]["processing"]
    assert stats["count"] == 20
    assert stats["mean_ms"] == 10.5
    assert stats["median_ms"] == 10.5
    assert stats["p95_ms"] == 19.05
    assert stats["min_ms"] == 1
    assert stats["max_ms"] == 20


def test_json_results_are_valid_and_accuracy_calculation_is_unchanged(tmp_path, monkeypatch):
    import evals.performance as performance

    monkeypatch.setattr(performance, "environment_metadata", lambda: {
        "python_version": "test", "total_system_memory_mib": None,
    })
    details_path, summary_path = write_performance_results([], tmp_path)
    assert json.loads(details_path.read_text(encoding="utf-8"))["scenarios"] == []
    assert json.loads(summary_path.read_text(encoding="utf-8"))["summary"]["scenarios_attempted"] == 0

    snapshot = PageSnapshot(url="", screenshot=b"", elements=[
        Element(id="a", tag="input", attrs={"css_selector": "#a"}),
        Element(id="b", tag="input", attrs={"css_selector": "#b"}),
    ])
    metrics = eval_detection.calculate_accuracy(
        [{"element_id_selector": "#a", "type": "EMAIL"},
         {"element_id_selector": "#b", "type": "CARD"}],
        snapshot,
        [Detection(type="EMAIL", element_id="a"), Detection(type="PHONE", element_id="b")],
    )
    assert metrics == {"recall": 0.5, "precision": 0.5, "tp": 1, "fp": 1, "fn": 1}
