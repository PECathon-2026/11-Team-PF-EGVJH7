"""Detect suspicious prompt-injection instructions in webpage content."""

from dataclasses import dataclass
import re


@dataclass
class InjectionFinding:
    flagged: bool
    category: str
    reason: str
    matched_rule: str


INJECTION_PATTERNS = [
    (
        "instruction_override",
        re.compile(
            r"\bignore\s+(all\s+)?(previous|prior|above)\s+"
            r"(instructions?|rules?|prompts?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        re.compile(
            r"\bdisregard\s+(all\s+)?(previous|prior|system)\s+"
            r"instructions?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_prompt_extraction",
        re.compile(
            r"\b(reveal|print|show|disclose|leak)\b.{0,60}"
            r"\b(system prompt|hidden prompt|secret instructions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "secret_exfiltration",
        re.compile(
            r"\b(send|transmit|upload|exfiltrate|forward)\b.{0,80}"
            r"\b(passwords?|credentials?|api keys?|card numbers?|"
            r"secrets?|tokens?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "concealment",
        re.compile(
            r"\b(do not tell|don't tell|hide this from|"
            r"without informing)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_override",
        re.compile(
            r"\byou are now\s+(an?\s+)?"
            r"(unrestricted|different|new)\s+(ai|assistant|agent)\b",
            re.IGNORECASE,
        ),
    ),
]


def detect_injection(text):
    """Return findings for suspicious instruction patterns."""
    if not isinstance(text, str) or not text:
        return []

    findings = []

    for category, pattern in INJECTION_PATTERNS:
        for _match in pattern.finditer(text):
            findings.append(
                InjectionFinding(
                    flagged=True,
                    category=category,
                    reason=(
                        "Webpage content matches a suspicious "
                        "instruction pattern."
                    ),
                    matched_rule=pattern.pattern,
                )
            )

    return findings


def get_value(obj, key, default=None):
    """Read a value from a dictionary or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def scan_page_elements(elements):
    """Scan webpage element text fields for suspicious instructions."""
    results = []
    fields = ("text", "value", "label", "placeholder", "title")

    for element in elements or []:
        element_id = str(get_value(element, "id", "") or "")

        for field_name in fields:
            value = get_value(element, field_name)

            if not isinstance(value, str):
                continue

            for finding in detect_injection(value):
                results.append({
                    "element_id": element_id,
                    "field": field_name,
                    "flagged": finding.flagged,
                    "category": finding.category,
                    "reason": finding.reason,
                    "matched_rule": finding.matched_rule,
                })

    return results
