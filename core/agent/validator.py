from contracts.models import Action, SanitizedView, ValidationResult


def validate(action: Action, view: SanitizedView) -> ValidationResult:
    """
    Phase 1 validator:
    Check that the action targets an element present in the
    sanitized webpage view.
    """

    if action.type == "done":
        return ValidationResult(ok=True)

    if not action.element_id:
        return ValidationResult(
            ok=False,
            reasons=["Action is missing an element ID."]
        )

    element_ids = {element.id for element in view.elements}

    if action.element_id not in element_ids:
        return ValidationResult(
            ok=False,
            reasons=[
    f"Element ID '{action.element_id}' does not exist in the sanitized view."
]
        )

    return ValidationResult(ok=True)
