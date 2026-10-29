"""Resource sampling and stable performance summaries for local evaluations."""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import threading
import time
from pathlib import Path

MIB = 1024 * 1024
LATENCY_FIELDS = (
    "browser_startup",
    "page_load",
    "snapshot",
    "detection",
    "sanitization",
    "processing",
    "end_to_end",
)


def resource_snapshot() -> dict:
    """Return process/system resource readings, using None when unavailable."""
    data = {
        "process_rss_mib": None,
        "available_system_memory_mib": None,
        "total_system_memory_mib": None,
        "cpu_core_count": None,
    }
    try:
        import psutil

        try:
            data["process_rss_mib"] = psutil.Process(os.getpid()).memory_info().rss / MIB
        except (OSError, psutil.Error):
            pass
        try:
            memory = psutil.virtual_memory()
            data["available_system_memory_mib"] = memory.available / MIB
            data["total_system_memory_mib"] = memory.total / MIB
        except (OSError, psutil.Error):
            pass
        try:
            data["cpu_core_count"] = psutil.cpu_count(logical=True)
        except (OSError, psutil.Error):
            pass
    except ImportError:
        pass
    return data


class PeakRssSampler:
    """Periodically sample this process's RSS; peak is necessarily an estimate."""

    def __init__(self, interval_seconds: float = 0.05):
        self.interval_seconds = interval_seconds
        self.peak_rss_mib = None
        self._stop = threading.Event()
        self._thread = None
        self._process = None

    def _sample(self):
        if self._process is None:
            return
        try:
            value = self._process.memory_info().rss / MIB
        except Exception:
            return
        if self.peak_rss_mib is None or value > self.peak_rss_mib:
            self.peak_rss_mib = value

    def start(self):
        try:
            import psutil

            self._process = psutil.Process(os.getpid())
            self._sample()
        except Exception:
            self._process = None
            return self

        def sample_loop():
            while not self._stop.wait(self.interval_seconds):
                self._sample()

        self._thread = threading.Thread(target=sample_loop, name="privacylens-rss-sampler", daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval_seconds * 4))
        self._sample()
        return self.peak_rss_mib


def new_scenario_record(name: str) -> dict:
    return {
        "scenario": name,
        "elements_processed": None,
        "sensitive_detections": None,
        "redactions": None,
        "success": False,
        "error": None,
        "latency_ms": {field: None for field in LATENCY_FIELDS},
        "rss_mib": {
            "before": None,
            "after": None,
            "change": None,
            "peak_sampled": None,
        },
    }


def _latency_stats(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "mean_ms": None, "median_ms": None, "p95_ms": None,
                "min_ms": None, "max_ms": None}
    ordered = sorted(values)
    p95 = (statistics.quantiles(ordered, n=100, method="inclusive")[94]
           if len(ordered) >= 20 else None)
    return {
        "count": len(ordered),
        "mean_ms": statistics.fmean(ordered),
        "median_ms": statistics.median(ordered),
        "p95_ms": p95,
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
    }


def aggregate_scenarios(scenarios: list[dict]) -> dict:
    """Aggregate metrics without treating unavailable values as zero."""
    summary = {
        "scenarios_attempted": len(scenarios),
        "scenarios_succeeded": sum(bool(row.get("success")) for row in scenarios),
        "scenarios_failed": sum(not bool(row.get("success")) for row in scenarios),
        "latency_ms": {},
    }
    for field in LATENCY_FIELDS:
        values = [row.get("latency_ms", {}).get(field) for row in scenarios]
        summary["latency_ms"][field] = _latency_stats(
            [value for value in values if isinstance(value, (int, float)) and value >= 0]
        )

    after_values = [row.get("rss_mib", {}).get("after") for row in scenarios]
    peak_values = [row.get("rss_mib", {}).get("peak_sampled") for row in scenarios]
    after_values = [value for value in after_values if isinstance(value, (int, float)) and value >= 0]
    peak_values = [value for value in peak_values if isinstance(value, (int, float)) and value >= 0]
    summary["rss_mib"] = {
        "mean_after_scenario": statistics.fmean(after_values) if after_values else None,
        "maximum_after_scenario": max(after_values) if after_values else None,
        "maximum_sampled_peak": max(peak_values) if peak_values else None,
        "sampled_peak_is_estimate": True,
        "rss_includes_python_and_resident_dependencies": True,
    }
    return summary


def environment_metadata() -> dict:
    resources = resource_snapshot()
    return {
        "python_version": sys.version.split()[0],
        "operating_system": platform.system(),
        "platform": platform.platform(),
        "cpu_core_count": resources["cpu_core_count"],
        "available_system_memory_mib": resources["available_system_memory_mib"],
        "total_system_memory_mib": resources["total_system_memory_mib"],
        "memory_unit": "MiB (bytes / 1,048,576)",
        "sampled_peak_rss_note": "RSS belongs to this Python process and resident dependencies; periodic sampling can miss short-lived spikes.",
    }


def write_performance_results(scenarios: list[dict], results_dir="results") -> tuple[Path, Path]:
    """Write stable JSON artifacts containing metadata and no page values."""
    output_dir = Path(results_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    details_path = output_dir / "performance_metrics.json"
    summary_path = output_dir / "performance_summary.json"
    details = {
        "schema_version": 1,
        "environment": environment_metadata(),
        "scenarios": scenarios,
    }
    summary = {
        "schema_version": 1,
        "environment": details["environment"],
        "summary": aggregate_scenarios(scenarios),
    }
    for path, payload in ((details_path, details), (summary_path, summary)):
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return details_path, summary_path


def elapsed_ms(start: float, end: float) -> float:
    """Convert perf_counter timestamps into a non-negative millisecond value."""
    return max(0.0, (end - start) * 1000.0)
