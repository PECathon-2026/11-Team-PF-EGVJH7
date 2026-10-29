import base64

from contracts.models import Action


def build_request(view, task, history, secret_names):
    """
    Build an AI request using only the sanitized webpage view.
    """

    elements = []

    for element in view.elements:
        if hasattr(element, "model_dump"):
            elements.append(element.model_dump())
        else:
            elements.append(element.dict())

    screenshot_b64 = base64.b64encode(
        view.screenshot
    ).decode("utf-8")

    return {
        "task": task,
        "url": view.url,
        "elements": elements,
        "screenshot_b64": screenshot_b64,
        "history": history,
        "secret_names": secret_names,
    }


def call_llm(request):
    """
    Phase 1 mock AI: return an action to click the Pay button.
    No real AI API is called in Phase 1.
    """

    for element in request["elements"]:
        text = str(element.get("text", ""))
        label = str(element.get("label") or "")
        element_id = element.get("id")
        tag = str(element.get("tag", "")).lower()
        role = str(element.get("role") or "").lower()
        element_type = str(element.get("type") or "").lower()

        button_text = f"{text} {label}".strip().lower()

        if (
            element_id
            and "pay" in button_text
            and (
                tag == "button"
                or role == "button"
                or element_type == "submit"
            )
        ):
            return Action(
                type="click",
                element_id=element_id,
                reason="Phase 1 mock action: click the Pay button."
            )

    return Action(
        type="done",
        reason="Mock action stopped: no suitable Pay button was found."
    )
