
from core.guard.egress import check_egress


def test_allows_safe_text():
    assert check_egress("Continue to the next page").ok


def test_blocks_email_in_nested_dictionary():
    result = check_egress({
        "request": {
            "page": {
                "contact": "student@example.com",
            }
        }
    })

    assert not result.ok


def test_blocks_phone_in_nested_list():
    result = check_egress({
        "history": [
            {"details": ["Contact number: 9876543210"]}
        ]
    })

    assert not result.ok


def test_blocks_unsupported_payload_type():
    result = check_egress(object())

    assert not result.ok


def test_blocks_excessively_nested_payload():
    payload = "safe"
    for _ in range(35):
        payload = [payload]

    result = check_egress(payload)

    assert not result.ok
