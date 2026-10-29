from playwright.sync_api import sync_playwright

from contracts.models import BBox, Element, PageSnapshot


def take_snapshot(url: str, headless: bool = True) -> PageSnapshot:
    """
    Open a webpage and capture its screenshot and interactive elements.

    Args:
        url: The webpage URL to inspect.
        headless: Whether to run Chromium without displaying its window.

    Returns:
        A PageSnapshot containing the URL, title, screenshot, and elements.
    """
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)

        try:
            page = browser.new_page(
                viewport={"width": 1280, "height": 800}
            )
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(500)

            screenshot = page.screenshot(full_page=False)

            raw_elements = page.locator(
                "button, input, textarea, select, a, "
                "[role='button'], [contenteditable='true']"
            ).evaluate_all(
                """elements => elements.map((el, index) => {
                    const rect = el.getBoundingClientRect();

                    return {
                        id: el.id || `element-${index}`,
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

            return PageSnapshot(
                url=page.url,
                title=page.title(),
                screenshot=screenshot,
                elements=elements,
            )

        finally:
            browser.close()

