"""Human approval gate for sensitive or consequential actions."""


def _safe_action_summary(action) -> str:
    """Describe an action without exposing typed or secret values."""
    action_type = getattr(action, "type", "unknown")
    element_id = getattr(action, "element_id", None)
    reason = getattr(action, "reason", None)

    descriptions = {
        "click": "Click the specified page element",
        "type": "Enter text into the specified field",
        "select": "Choose an option in the specified field",
        "scroll": "Scroll the current page",
        "navigate": "Navigate to another page",
        "done": "Finish the current task",
    }

    summary = descriptions.get(
        action_type,
        "Perform an action on the current page",
    )

    lines = [
        f"Action: {summary}",
        f"Action type: {action_type}",
        f"Target element ID: {element_id or 'N/A'}",
    ]

    if action_type == "navigate":
        lines.append("Navigation target: See the validated destination.")

    if reason:
        # Avoid printing arbitrary model-generated text, which could
        # contain sensitive information.
        lines.append("Reason: The action was flagged as consequential.")

    return "\n".join(lines)

def needs_approval(action, element) -> bool:
    """Check whether an action needs explicit human approval."""
    if action.type != "click" or element is None:
        return False

    attrs = element.attrs or {}

    details = " ".join([
        element.name or "",
        element.label or "",
        element.text or "",
        str(attrs.get("value", "")),
        str(attrs.get("type", "")),
    ]).lower()

    keywords = (
        "pay", "payment", "purchase", "buy now",
        "place order", "submit", "confirm order",
        "checkout", "transfer",
    )

    return any(keyword in details for keyword in keywords)


def request_approval(action) -> bool:
    """Require an explicit YES before a sensitive action can execute."""
    print("\nPRIVACYLENS: APPROVAL REQUIRED")
    print(_safe_action_summary(action))
    print("Review the action carefully before approving.")

    try:
        answer = input("Type YES to approve, or anything else to reject: ")
    except (EOFError, KeyboardInterrupt):
        return False

    return answer.strip() == "YES"