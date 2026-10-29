
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = {
    "mode": "mock",
    "model": "gemini-3.5-flash-lite",
    "allowed_domains": ["localhost", "127.0.0.1"],
    "max_steps": 10,
}


def load_config(path=None):
    """Load and validate PrivacyLens configuration."""
    config_path = Path(path) if path else ROOT / "config.yaml"

    try:
        with config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
    except OSError as exc:
        raise ValueError(f"Cannot read configuration: {config_path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError("Invalid config.yaml syntax.") from exc

    if not isinstance(data, dict):
        raise ValueError("Configuration must be a YAML mapping.")

    config = {**DEFAULT_CONFIG, **data}

    if config["mode"] not in {"mock", "real"}:
        raise ValueError("mode must be 'mock' or 'real'.")

    domains = config["allowed_domains"]
    if (
        not isinstance(domains, list)
        or not domains
        or any(not isinstance(d, str) or not d.strip() for d in domains)
    ):
        raise ValueError("allowed_domains must be a non-empty list of domains.")

    config["allowed_domains"] = [
        domain.strip().lower().rstrip(".") for domain in domains
    ]

    steps = config["max_steps"]
    if not isinstance(steps, int) or isinstance(steps, bool) or steps < 1:
        raise ValueError("max_steps must be a positive integer.")

    if not isinstance(config["model"], str) or not config["model"].strip():
        raise ValueError("model must be a non-empty string.")

    return config
