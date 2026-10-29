"""Capture browser state for the PrivacyLens privacy pipeline."""

from playwright.sync_api import Page
from uuid import uuid4

from contracts.models import BBox, Element, PageSnapshot


def take_snapshot(page: Page, timeout_ms: int = 30000) -> PageSnapshot:
    """
    Capture a page snapshot without launching or closing the browser.

    Interactive elements receive stable generated IDs (e1, e2, ...).
    Original DOM attributes are retained separately for privacy rules.
    """

    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30000:
        raise ValueError("timeout_ms must be between 1 and 30000.")

    # Apply the workflow's bound to Playwright operations that honor the
    # page-level default, and pass it explicitly to screenshot capture below.
    page.set_default_timeout(timeout_ms)

    # Assign stable IDs to interactive elements in DOM order.
    snapshot_id = uuid4().hex
    raw_elements = page.locator(
        "button, input, textarea, select, a, "
        "[role='button'], [contenteditable='true']"
    ).evaluate_all(
        """(elements, snapshotId) => elements.map((el, index) => {
            const id = `e${index + 1}`;

            // This is an internal locator, not the element's original DOM ID.
            el.setAttribute("data-pl-id", id);
            el.setAttribute("data-pl-snapshot", snapshotId);

            const rect = el.getBoundingClientRect();

            const attributes = Object.fromEntries(
                Array.from(el.attributes).map(
                    attr => [attr.name, attr.value]
                )
            );

            return {
                id,
                tag: el.tagName.toLowerCase(),
                role: el.getAttribute("role"),
                type: el.getAttribute("type"),
                name: el.getAttribute("name"),
                label: el.getAttribute("aria-label")
                    || el.labels?.[0]?.innerText
                    || "",
                placeholder: el.getAttribute("placeholder") || "",
                // Form control values are captured separately; treating their
                // default textContent as visible text duplicates textarea data.
                text: (el.matches('input, textarea, select') ? '' :
                    (el.innerText || el.textContent || '')).trim(),
                value: el.value || "",
                bbox: {
                    x: rect.x,
                    y: rect.y,
                    w: rect.width,
                    h: rect.height
                },
                attrs: {
                    placeholder: el.getAttribute("placeholder") || "",
                    autocomplete: el.getAttribute("autocomplete") || "",
                    href: el.getAttribute("href") || "",
                    disabled: Boolean(el.disabled),
                    readonly: Boolean(el.readOnly)
                },
                attributes
            };
        })""",
        snapshot_id,
    )

    elements = [
        Element(
            id=item["id"],
            tag=item["tag"],
            role=item["role"],
            type=item["type"],
            name=item["name"],
            label=item["label"],
            placeholder=item["placeholder"],
            text=item["text"],
            value=item["value"],
            bbox=BBox(**item["bbox"]),
            attrs=item["attrs"],
            attributes=item["attributes"],
        )
        for item in raw_elements
    ]

    # Capture common visible text containers too; otherwise plain page copy
    # (including sensitive values) never reaches detection or text sanitization.
    raw_text_regions = page.locator(
        "p, h1, h2, h3, h4, h5, h6, li, blockquote, svg, [role='img']"
    ).evaluate_all(
        """nodes => nodes.map((el, index) => {
            const style = getComputedStyle(el);
            const text = (el.innerText || el.textContent || '').trim();
            if (!text || !el.getClientRects().length || style.display === 'none'
                || style.visibility === 'hidden' || style.opacity === '0') return null;
            const rect = el.getBoundingClientRect();
            return {
                id: `text${index + 1}`,
                tag: el.tagName.toLowerCase(),
                text,
                bbox: {x: rect.x, y: rect.y, w: rect.width, h: rect.height}
            };
        }).filter(Boolean)"""
    )
    elements.extend(
        Element(
            id=item["id"], tag=item["tag"], text=item["text"],
            bbox=BBox(**item["bbox"]),
        )
        for item in raw_text_regions
    )

    # Capture after IDs have been injected so the screenshot and
    # element list represent the same page state.
    screenshot = page.screenshot(full_page=False, timeout=timeout_ms)

    viewport = page.evaluate("""() => ({width: window.innerWidth, height: window.innerHeight,
        dpr: window.devicePixelRatio || 1})""")
    return PageSnapshot(
        url=page.url,
        title=page.title(),
        screenshot=screenshot,
        elements=elements,
        viewport_size=(viewport["width"], viewport["height"]),
        device_pixel_ratio=viewport["dpr"],
        snapshot_id=snapshot_id,
    )
