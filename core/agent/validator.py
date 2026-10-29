from contracts.models import Action, SanitizedView, ValidationResult
from core.browser.navigation import validate_navigation_url


def validate(action: Action, view: SanitizedView) -> ValidationResult:
    """
    Phase 1 validator:
    Check that the action targets an element present in the
    sanitized webpage view.
    """

    if action.type == "done":
        ok = (not action.element_id and not action.url and action.text is None
              and action.secret_ref is None)
        return ValidationResult(ok=ok, reasons=[] if ok else ["Done action contains extra payload."])

    if action.secret_ref is not None:
        return ValidationResult(ok=False, reasons=["Secret references are not enabled."])

    if action.type == "scroll":
        ok = not action.element_id and action.url is None and action.text is None
        return ValidationResult(ok=ok, reasons=[] if ok else ["Scroll action contains unsupported payload."])

    if action.type == "navigate":
        try:
            validate_navigation_url(action.url)
            ok = not action.element_id and action.text is None and action.secret_ref is None
        except ValueError:
            ok = False
        return ValidationResult(ok=ok, reasons=[] if ok else ["Navigation URL is not allowed."])

    if not action.element_id:
        return ValidationResult(
            ok=False,
            reasons=["Action is missing an element ID."]
        )

    elements = {element.id: element for element in view.elements}
    if action.element_id not in elements:
        return ValidationResult(
            ok=False,
            reasons=[
    f"Element ID '{action.element_id}' does not exist in the sanitized view."
]
        )

    element = elements[action.element_id]
    if action.type == "click":
        ok = element.tag == "a" and action.text is None and action.url is None
        return ValidationResult(ok=ok, reasons=[] if ok else ["Only navigable links may be clicked."])
    if action.type == "type":
        ok = (element.tag in {"input", "textarea"} and element.type != "password"
              and element.type != "hidden" and action.text is not None and action.url is None)
        return ValidationResult(ok=ok, reasons=[] if ok else ["Typing is not allowed for this target or payload."])
    if action.type == "select":
        ok = element.tag == "select" and action.text is not None and action.url is None
        return ValidationResult(ok=ok, reasons=[] if ok else ["Select action does not match its target."])
    return ValidationResult(ok=False, reasons=["Unsupported action."])
