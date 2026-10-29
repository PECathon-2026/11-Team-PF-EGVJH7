"""Model-bound sanitization, synthetic substitution and final egress gate.

PrivateMapping is separate from the serializable payload. Callers must
retain it only in trusted execution state and never pass it to an LLM.
"""

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
    """Trusted-only synthetic-to-original mapping for one task."""

    synthetic_to_original: dict[str, str] = field(
        default_factory=dict,
        repr=False,
    )

    def restore(
        self,
        synthetic_value: str,
        *,
        allowed: bool = False,
    ) -> str:
        if not allowed:
            raise PermissionError(
                "Restoring protected values requires authorization."
            )

        if synthetic_value not in self.synthetic_to_original:
            raise KeyError(
                "No authorized mapping exists for this value."
            )

        return self.synthetic_to_original[synthetic_value]


@dataclass
class ModelPayload:
    payload: dict[str, Any]
    private_mapping: PrivateMapping
    report: list[dict[str, Any]]
    audit: PrivacyAuditLog


def _get(obj: Any, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


def _harden_sensitive_attributes(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Scrub raw DOM attributes that commonly duplicate secrets."""

    sensitive_key = re.compile(
        r"(?:password|passwd|secret|token|api.?key|card.?number|"
        r"cvv|cvc|otp|one.?time.?code|credential)",
        re.I,
    )

    for element in payload.get("elements", []):
        if not isinstance(element, dict):
            continue

        field_type = str(
            element.get("type") or ""
        ).lower()

        for container_name in ("attributes", "attrs"):
            attributes = element.get(container_name)

            if not isinstance(attributes, dict):
                continue

            for key in list(attributes):
                key_text = str(key)

                if sensitive_key.search(key_text):
                    attributes[key] = "[PROTECTED:ATTRIBUTE]"

                elif (
                    field_type in {
                        "password",
                        "otp",
                        "one-time-code",
                    }
                    and key_text.lower()
                    in {"value", "defaultvalue"}
                ):
                    attributes[key] = "[PROTECTED:ATTRIBUTE]"

    return payload


def _replace_recursive(
    value: Any,
    replacements: dict[str, str],
):
    """Replace secrets throughout nested payload structures."""

    if isinstance(value, str):
        result = value

        for original in sorted(
            replacements,
            key=len,
            reverse=True,
        ):
            result = result.replace(
                original,
                replacements[original],
            )

        return result

    if isinstance(value, dict):
        return {
            _replace_recursive(key, replacements):
            _replace_recursive(item, replacements)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _replace_recursive(item, replacements)
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            _replace_recursive(item, replacements)
            for item in value
        )

    if isinstance(value, (set, frozenset)):
        return {
            _replace_recursive(item, replacements)
            for item in value
        }

    return value


def build_model_payload(
    snapshot: Any,
    detections: list[Any],
    *,
    synthetic_factory: Callable[[str, str], str] | None = None,
    rules_path=None,
    task_intent: str = "",
    canaries=(),
) -> ModelPayload:
    """Build a safe payload and block it if privacy checks fail."""

    detection_list = list(detections or [])

    view = sanitize(
        snapshot,
        detection_list,
        rules_path=rules_path,
    )

    original_elements = list(
        _get(snapshot, "elements", []) or []
    )

    private = PrivateMapping()
    replacements: dict[str, str] = {}
    audit = PrivacyAuditLog()

    # Build replacements from the detected portions of element fields.
    for det in detection_list:
        element_id = _get(det, "element_id")
        field_name = _get(det, "field", "value")
        dtype = normalize_type(
            _get(det, "type", "SECRET")
        )
        span = _get(det, "span")

        for element in original_elements:
            if str(_get(element, "id", "")) != str(element_id):
                continue

            original_text = _get(element, field_name, "")

            if not isinstance(original_text, str) or not original_text:
                continue

            if (
                isinstance(span, (tuple, list))
                and len(span) == 2
            ):
                start, end = span

                if (
                    type(start) is int
                    and type(end) is int
                    and 0 <= start < end <= len(original_text)
                ):
                    secret = original_text[start:end]
                else:
                    secret = original_text
            else:
                secret = original_text

            if not secret:
                continue

            existing_fake = replacements.get(secret)

            if existing_fake is None:
                if synthetic_factory is not None:
                    fake = synthetic_factory(dtype, secret)
                else:
                    fake = placeholder_for(dtype)

                if (
                    not isinstance(fake, str)
                    or not fake
                    or fake == secret
                ):
                    raise ValueError(
                        "Synthetic generator returned an unsafe replacement."
                    )

                existing_original = (
                    private.synthetic_to_original.get(fake)
                )

                if (
                    existing_original is not None
                    and existing_original != secret
                ):
                    raise ValueError(
                        "Synthetic generator collision detected; "
                        "refusing ambiguous mapping."
                    )

                replacements[secret] = fake
                private.synthetic_to_original[fake] = secret

            audit.record(
                event="secret_detected",
                category="sensitive_data",
                technique="synthetic_replacement",
                decision="allowed",
                reason="Sensitive value replaced before model-bound serialization.",
            )

    # Serialize only model-visible data. Never serialize PrivateMapping.
    payload = {
        "url": view.url,
        "title": view.title,
        "elements": [
            element.model_dump(mode="json")
            if hasattr(element, "model_dump")
            else deepcopy(element)
            for element in view.elements
        ],
        "screenshot_sha256": view.screenshot_sha256,
        "report": deepcopy(view.report),
        "task_intent": str(task_intent or ""),
    }

    payload = _replace_recursive(
        payload,
        replacements,
    )

    payload = _harden_sensitive_attributes(payload)

    # Replace redaction placeholders only when the synthetic value is
    # unambiguous for this specific element field and detected type.
    for det in detection_list:
        element_id = str(
            _get(det, "element_id", "")
        )
        field_name = str(
            _get(det, "field", "value")
        )
        dtype = normalize_type(
            _get(det, "type", "SECRET")
        )

        candidates = []

        for other in detection_list:
            if (
                str(_get(other, "element_id", "")) != element_id
                or str(_get(other, "field", "value")) != field_name
            ):
                continue

            other_type = normalize_type(
                _get(other, "type", "SECRET")
            )
            other_span = _get(other, "span")

            for original_element in original_elements:
                if (
                    str(_get(original_element, "id", ""))
                    != element_id
                ):
                    continue

                raw_field = _get(
                    original_element,
                    field_name,
                    "",
                )

                if not isinstance(raw_field, str):
                    continue

                if (
                    isinstance(other_span, (tuple, list))
                    and len(other_span) == 2
                    and type(other_span[0]) is int
                    and type(other_span[1]) is int
                    and 0 <= other_span[0] < other_span[1]
                    <= len(raw_field)
                ):
                    raw_secret = raw_field[
                        other_span[0]:other_span[1]
                    ]
                else:
                    raw_secret = raw_field

                if raw_secret in replacements:
                    candidates.append(
                        (
                            other_type,
                            replacements[raw_secret],
                        )
                    )

        unique_for_type = {
            fake
            for kind, fake in candidates
            if kind == dtype
        }

        if len(unique_for_type) != 1:
            continue

        fake = next(iter(unique_for_type))
        token = placeholder_for(dtype)

        for item in payload["elements"]:
            if (
                str(item.get("id", "")) == element_id
                and isinstance(item.get(field_name), str)
            ):
                item[field_name] = item[field_name].replace(
                    token,
                    fake,
                )

    # Final fail-closed egress check.
    secrets = list(replacements.keys())

    result = validate_outgoing(
        payload,
        secrets,
        canaries=canaries,
    )

    if not result.ok:
        audit.record(
            event="egress_check",
            category="outgoing_payload",
            technique="leakage_validation",
            decision="blocked",
            reason="Final payload failed leakage validation.",
        )
        raise ValueError(
            f"Privacy firewall blocked outgoing payload. Reasons: {result.reasons}; leak_count: {len(result.leaks)}"
        )
    audit.record(
        event="egress_check",
        category="outgoing_payload",
        technique="leakage_validation",
        decision="allowed",
        reason="Final payload passed original-secret leakage validation.",
    )

    return ModelPayload(
        payload=payload,
        private_mapping=private,
        report=view.report,
        audit=audit,
    )