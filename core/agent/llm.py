import base64

from contracts.models import Action


def build_request(view, task, history, secret_names):
    """
    Build an AI request using only the sanitized webpage view.
    """

    elements = []

    for element in view.elements:
        data = element.model_dump() if hasattr(element, "model_dump") else element.dict()
        # Attribute names and the page URL can contain user-specific data.
        # Neither is needed by the current mock agent, so omit them entirely.
        elements.append({key: data.get(key) for key in (
            "id", "tag", "role", "type", "label", "placeholder",
            "text", "value", "bbox",
        )})

    screenshot_b64 = base64.b64encode(
        view.screenshot
    ).decode("utf-8")

    return {
        "task": task,
        "elements": elements,
        "screenshot_b64": screenshot_b64,
        "history": history,
        "secret_names": secret_names,
    }


def call_llm(request):
    """Return a deterministic, harmless mock action; no provider is called."""

    if not request.get("history"):
        return Action(type="scroll", reason="Mock workflow performs one harmless scroll.")

    return Action(
        type="done",
        reason="Mock workflow reached its safe termination condition."
    )
