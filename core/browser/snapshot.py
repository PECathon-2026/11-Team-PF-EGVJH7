from playwright.sync_api import Page

from contracts.models import BBox, Element, PageSnapshot


def take_snapshot(page: Page) -> PageSnapshot:
    """
    Capture a snapshot of an existing Playwright page.

    The caller owns the browser lifecycle. This function does not
    launch or close the browser.

    Each interactive element receives a stable data-pl-id attribute
    such as e1, e2, e3, which can be used by the executor.
    """

    # Assign stable IDs to interactive elements in DOM order.
    raw_elements = page.locator(
        "button, input, textarea, select, a, "
        "[role='button'], [contenteditable='true']"
    ).evaluate_all(
        """elements => elements.map((el, index) => {
            const id = `e${index + 1}`;

            // Inject a stable ID that the executor can query.
            el.setAttribute("data-pl-id", id);

            const rect = el.getBoundingClientRect();

            return {
                id,
                tag: el.tagName.toLowerCase(),
                role: el.getAttribute("role"),
                type: el.getAttribute("type"),
                name: el.getAttribute("name"),
                label: el.getAttribute("aria-label")
                    || el.labels?.[0]?.innerText
                    || "",
                text: (el.innerText || el.textContent || "").trim(),
                value: el.value || "",
                bbox: {
                    x: rect.x,
                    y: rect.y,
                    w: rect.width,
                    h: rect.height
                },
                attrs: {
                    placeholder: el.getAttribute("placeholder") || "",
                    autocomplete: el.getAttribute("autocomplete") || ""
                }
            };
        })"""
    )

    elements = [
        Element(
            id=item["id"],
            tag=item["tag"],
            role=item["role"],
            type=item["type"],
            name=item["name"],
            label=item["label"],
            text=item["text"],
            value=item["value"],
            bbox=BBox(**item["bbox"]),
            attrs=item["attrs"],
        )
        for item in raw_elements
    ]

    # Capture after IDs have been injected so the screenshot and
    # element list represent the same page state.
    screenshot = page.screenshot(full_page=False)

    return PageSnapshot(
        url=page.url,
        title=page.title(),
        screenshot=screenshot,
        elements=elements,
    )