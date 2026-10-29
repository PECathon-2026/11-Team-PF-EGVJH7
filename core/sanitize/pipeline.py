"""Build privacy-safe payloads for outgoing model requests."""

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable
import re

from core.guard.egress import validate_outgoing
from core.guard.audit import PrivacyAuditLog
from . import sanitize
from .rules import normalize_type, placeholder_for


@dataclass
class PrivateMapping:
    """Keep original values separate from the outgoing payload."""

    synthetic_to_original: dict[str, str] = field(default_factory=dict, repr=False)

    def restore(self, synthetic_value: str, allowed: bool = False) -> str:
        """Restore an original value only when explicitly authorized."""
        if not allowed:
            raise PermissionError("Restoring private values requires explicit authorization.")
        if synthetic_value not in self.synthetic_to_original:
            raise KeyError("Unknown synthetic value.")
        return self.synthetic_to_original[synthetic_value]


@dataclass
class ModelPayload:
    """Sanitized payload and local-only privacy metadata."""

    payload: dict[str, Any]
    private_mapping: PrivateMapping
    report: list[dict[str, Any]]
    audit: PrivacyAuditLog


def _get(obj, key, default=None):
    """Read a value from either a dictionary or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _harden_sensitive_attributes(payload):
    """Protect sensitive fields and DOM attributes in the outgoing payload."""
    sensitive_key = re.compile(
        r"(?:password|passwd|secret|token|api.?key|card.?number|"
        r"cvv|cvc|otp|one.?time.?code|credential)",
        re.IGNORECASE,
    )

    for element in payload.get("elements", []):
        if not isinstance(element, dict):
            continue

        field_type = str(element.get("type") or "").lower()
        is_sensitive_field = field_type in {"password", "otp", "one-time-code"}

        if is_sensitive_field:
            for field_name in ("value", "text", "label", "placeholder", "title"):
                value = element.get(field_name)
                if isinstance(value, str) and value:
                    element[field_name] = "[PROTECTED:FIELD]"

        for container_name in ("attributes", "attrs"):
            attributes = element.get(container_name)
            if not isinstance(attributes, dict):
                continue

            for key in list(attributes):
                key_text = str(key)
                if sensitive_key.search(key_text):
                    attributes[key] = "[PROTECTED:ATTRIBUTE]"
                elif is_sensitive_field and key_text.lower() in {"value", "defaultvalue"}:
                    attributes[key] = "[PROTECTED:ATTRIBUTE]"

    return payload


def _replace_recursive(value, replacements):
    """Replace original sensitive values recursively."""
    if isinstance(value, str):
        result = value
        for original in sorted(replacements, key=len, reverse=True):
            if original:
                result = result.replace(original, replacements[original])
        return result
    if isinstance(value, dict):
        return {
            _replace_recursive(key, replacements): _replace_recursive(item, replacements)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_replace_recursive(item, replacements) for item in value]
    if isinstance(value, tuple):
        return tuple(_replace_recursive(item, replacements) for item in value)
    if isinstance(value, set):
        return {_replace_recursive(item, replacements) for item in value}
    return value


def _apply_synthetic_replacements_to_spans(
    serialized_elements, original_elements, detections, replacements
):
    """Apply synthetic values to valid detected spans before global replacement.

    Sanitization may have replaced a detected span with a generic redaction
    marker. Reconstruct only fields whose detections all have valid,
    non-overlapping spans; invalid or overlapping fields remain sanitized.
    """
    original_by_id = {
        str(_get(element, "id", "")): element for element in original_elements
    }
    serialized_by_id = {
        str(element.get("id", "")): element
        for element in serialized_elements
        if isinstance(element, dict)
    }

    grouped = {}
    invalid_groups = set()

    for detection in detections:
        element_id = str(_get(detection, "element_id", ""))
        field_name = str(_get(detection, "field", "value") or "value")
        group_key = (element_id, field_name)
        original_element = original_by_id.get(element_id)
        if original_element is None:
            invalid_groups.add(group_key)
            continue

        original_text = _get(original_element, field_name)
        span = _get(detection, "span")
        if (
            not isinstance(original_text, str)
            or not isinstance(span, (tuple, list))
            or len(span) != 2
            or type(span[0]) is not int
            or type(span[1]) is not int
            or not (0 <= span[0] < span[1] <= len(original_text))
        ):
            invalid_groups.add(group_key)
            continue

        start, end = span
        original_secret = original_text[start:end]
        if not original_secret or original_secret not in replacements:
            invalid_groups.add(group_key)
            continue

        grouped.setdefault(group_key, []).append(
            (start, end, replacements[original_secret])
        )

    for group_key, spans in grouped.items():
        if group_key in invalid_groups:
            continue

        element_id, field_name = group_key
        original_element = original_by_id.get(element_id)
        serialized_element = serialized_by_id.get(element_id)
        if original_element is None or serialized_element is None:
            continue

        original_text = _get(original_element, field_name)
        if not isinstance(original_text, str):
            continue

        ordered_spans = sorted(spans, key=lambda item: (item[0], item[1]))
        if any(
            ordered_spans[index][1] > ordered_spans[index + 1][0]
            for index in range(len(ordered_spans) - 1)
        ):
            continue

        rebuilt_text = original_text
        for start, end, synthetic in reversed(ordered_spans):
            rebuilt_text = rebuilt_text[:start] + synthetic + rebuilt_text[end:]
        serialized_element[field_name] = rebuilt_text


def _collect_sensitive_values(elements):
    """Collect known secrets for outgoing-payload leakage validation."""
    sensitive_key = re.compile(
        r"(?:password|passwd|secret|token|api.?key|card.?number|"
        r"cvv|cvc|otp|one.?time.?code|credential)",
        re.IGNORECASE,
    )
    protected = []

    for element in elements:
        field_type = str(_get(element, "type", "") or "").lower()
        if field_type in {"password", "otp", "one-time-code"}:
            value = _get(element, "value")
            if isinstance(value, str) and value:
                protected.append(value)

        for container_name in ("attributes", "attrs"):
            attributes = _get(element, container_name, {})
            if not isinstance(attributes, dict):
                continue
            for key, value in attributes.items():
                sensitive_attribute = bool(sensitive_key.search(str(key)))
                sensitive_field_value = (
                    field_type in {"password", "otp", "one-time-code"}
                    and str(key).lower() in {"value", "defaultvalue"}
                )
                if (sensitive_attribute or sensitive_field_value) and isinstance(value, str) and value:
                    protected.append(value)

    return protected


def build_model_payload(
    snapshot,
    detections,
    rules_path=None,
    task_intent="",
    synthetic_factory: Callable[[str, str], str] | None = None,
    canaries=None,
):
    """Build, sanitize, and validate a payload for an outgoing model request."""
    detection_list = list(detections or [])
    original_elements = list(_get(snapshot, "elements", []) or [])
    view = sanitize(snapshot, detection_list, rules_path=rules_path)

    private_mapping = PrivateMapping()
    replacements = {}
    audit = PrivacyAuditLog()

    # Inventory all detected original values first so synthetic values cannot
    # accidentally equal another detected secret.
    detected_originals = set()
    for detection in detection_list:
        element_id = str(_get(detection, "element_id", ""))
        field_name = str(_get(detection, "field", "value") or "value")
        element = next(
            (item for item in original_elements
             if str(_get(item, "id", "")) == element_id),
            None,
        )
        if element is None:
            continue
        value = _get(element, field_name)
        span = _get(detection, "span")
        if not isinstance(value, str) or not value:
            continue
        if (
            isinstance(span, (tuple, list))
            and len(span) == 2
            and type(span[0]) is int
            and type(span[1]) is int
            and 0 <= span[0] < span[1] <= len(value)
        ):
            value = value[span[0]:span[1]]
        if value:
            detected_originals.add(value)

    for detection in detection_list:
        element_id = str(_get(detection, "element_id", ""))
        field_name = str(_get(detection, "field", "value") or "value")
        secret_type = normalize_type(_get(detection, "type", "SECRET"))
        original_element = next(
            (element for element in original_elements
             if str(_get(element, "id", "")) == element_id),
            None,
        )
        if original_element is None:
            continue

        original_value = _get(original_element, field_name)
        if not isinstance(original_value, str) or not original_value:
            continue

        span = _get(detection, "span")
        if (
            isinstance(span, (tuple, list))
            and len(span) == 2
            and type(span[0]) is int
            and type(span[1]) is int
            and 0 <= span[0] < span[1] <= len(original_value)
        ):
            original_value = original_value[span[0]:span[1]]
        if not original_value:
            continue

        if original_value not in replacements:
            synthetic = (
                synthetic_factory(secret_type, original_value)
                if synthetic_factory is not None
                else placeholder_for(secret_type)
            )
            if not isinstance(synthetic, str) or not synthetic:
                raise ValueError("Synthetic secret replacement must be a non-empty string.")

            # Fail closed if the generated value collides with an original
            # detected secret, or if one synthetic value is assigned to two
            # different original values. Repeated instances of the same
            # original value intentionally reuse the same synthetic value.
            if synthetic in detected_originals:
                raise ValueError("Synthetic value collision detected.")

            existing_original = private_mapping.synthetic_to_original.get(synthetic)
            if existing_original is not None and existing_original != original_value:
                raise ValueError("Synthetic value collision detected.")

            replacements[original_value] = synthetic
            private_mapping.synthetic_to_original[synthetic] = original_value

    serialized_elements = []
    for element in view.elements:
        if hasattr(element, "model_dump"):
            serialized = element.model_dump(mode="json")
        elif hasattr(element, "dict"):
            serialized = element.dict()
        elif isinstance(element, dict):
            serialized = deepcopy(element)
        else:
            raise ValueError("Sanitization failed: unsupported element representation.")
        serialized_elements.append(serialized)

    _apply_synthetic_replacements_to_spans(
        serialized_elements, original_elements, detection_list, replacements
    )

    payload = {
        "url": view.url,
        "title": view.title,
        "elements": serialized_elements,
        "screenshot_sha256": view.screenshot_sha256,
        "report": deepcopy(view.report),
        "task_intent": str(task_intent or ""),
    }
    payload = _replace_recursive(payload, replacements)
    payload = _harden_sensitive_attributes(payload)

    protected_secrets = list(replacements.keys())
    protected_secrets.extend(_collect_sensitive_values(original_elements))
    protected_secrets = list(dict.fromkeys(protected_secrets))
    canary_values = list(canaries or [])

    if not protected_secrets and not canary_values:
        audit.record(
            "egress_check", False,
            "No protected-value inventory available for validation.",
        )
        raise ValueError("Privacy firewall blocked the outgoing payload.")

    result = validate_outgoing(
        payload, secrets=protected_secrets, canaries=canary_values
    )
    if not result.ok:
        audit.record(
            "egress_check", False,
            "Final payload failed original-secret leakage validation.",
        )
        raise ValueError("Privacy firewall blocked the outgoing payload.")

    audit.record(
        "egress_check", True,
        "Final payload passed original-secret leakage validation.",
    )

    return ModelPayload(
        payload=payload,
        private_mapping=private_mapping,
        report=deepcopy(view.report),
        audit=audit,
    )
