from core.agent.llm import _mock_action


def test_mock_selects_card_field_not_pay_button():
    request = {
        "elements": [
            {
                "id": "e7",
                "tag": "button",
                "text": "Pay Now",
            },
            {
                "id": "card",
                "tag": "input",
                "name": "card",
                "label": "Card number",
                "attrs": {"autocomplete": "cc-number"},
            },
        ]
    }

    action = _mock_action(request)

    assert action.type == "type"
    assert action.element_id == "card"
    assert action.text == "DEMO-CARD-ONLY"


def test_mock_does_not_invent_card_field():
    action = _mock_action({"elements": []})

    assert action.type == "done"
    assert action.element_id is None