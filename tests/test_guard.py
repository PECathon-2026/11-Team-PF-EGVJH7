"""Unit tests for PrivacyLens outgoing-data security guards."""

import pytest

from core.guard import detect_canary_leak, validate_no_leakage


def test_egress_allows_payload_without_original_secret():
    result = validate_no_leakage(
        {"messages": [{"content": "Contact alex@example.com"}]},
        ["real.person@company.test"],
    )

    assert result.ok is True
    assert result.reasons == []


def test_egress_blocks_secret_in_nested_payload():
    secret = "fictional-card-secret-1234"

    result = validate_no_leakage(
        {"messages": [{"content": "value=" + secret}]},
        [secret],
    )

    assert result.ok is False
    assert secret not in " ".join(result.reasons)


def test_egress_blocks_secret_in_dictionary_key():
    secret = "hidden-secret-key"

    result = validate_no_leakage(
        {secret: "metadata"},
        [secret],
    )

    assert result.ok is False


def test_egress_fails_closed_for_empty_secret_inventory():
    result = validate_no_leakage(
        {"content": "safe"},
        [],
    )

    assert result.ok is False


def test_egress_fails_closed_for_invalid_secret_inventory():
    result = validate_no_leakage(
        {"content": "safe"},
        ["valid-secret", ""],
    )

    assert result.ok is False


def test_egress_does_not_echo_secret_in_result():
    secret = "sensitive-test-value"

    result = validate_no_leakage(
        {"content": secret},
        [secret],
    )

    assert result.ok is False
    assert secret not in repr(result.reasons)


def test_canary_blocks_marker_without_echoing_it():
    marker = "PRIVACYLENS_CANARY_TEST_7F3A"

    result = detect_canary_leak(
        {"content": "quoted " + marker},
        [marker],
    )

    assert result.ok is False
    assert marker not in repr(result.reasons)


def test_canary_allows_payload_without_marker():
    result = detect_canary_leak(
        {"content": "safe synthetic value"},
        ["CANARY-123"],
    )

    assert result.ok is True


def test_canary_fails_closed_for_empty_inventory():
    result = detect_canary_leak(
        {"content": "safe"},
        [],
    )

    assert result.ok is False


def test_canary_detects_marker_in_nested_metadata():
    marker = "TEST-CANARY-7788"

    result = detect_canary_leak(
        {
            "messages": [
                {
                    "content": "safe",
                    "metadata": {"quoted_value": marker},
                }
            ]
        },
        [marker],
    )

    assert result.ok is False


def test_egress_fails_closed_for_uninspectable_payload():
    result = validate_no_leakage(
        {"content": object()},
        ["known-secret"],
    )

    assert result.ok is False


def test_canary_fails_closed_for_uninspectable_payload():
    result = detect_canary_leak(
        {"content": object()},
        ["known-canary"],
    )

    assert result.ok is False