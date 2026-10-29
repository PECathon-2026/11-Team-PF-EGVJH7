
def request_approval(action) -> bool:
    """Ask the user for explicit approval before a sensitive action."""
    print("\nPRIVACYLENS: APPROVAL REQUIRED")
    print(f"Action: {action.type}")
    print(f"Target element: {action.element_id or 'N/A'}")
    print(f"Reason: {action.reason or 'Sensitive or consequential action'}")

    try:
        answer = input("Approve this action? Type YES to continue: ")
    except (EOFError, KeyboardInterrupt):
        return False

    return answer.strip() == "YES"
