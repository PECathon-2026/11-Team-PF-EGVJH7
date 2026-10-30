"""End-to-end tests of the browser extension in a real Chromium.

Loads extension/ unpacked, drives the real side panel against the testlab
pages, and checks the security guarantees at the page level (actual click
counts), not just in the UI.
"""

import json
import shutil
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright


REPO_ROOT = Path(__file__).resolve().parent.parent
EXTENSION_SRC = REPO_ROOT / "extension"
REAL_CARD = "4111 1111 1111 1111"
REAL_VALUES = [REAL_CARD, "test.user@example.com", "42 MG Road, Bengaluru"]

TRACK_PAY_CLICKS_JS = """() => {
    window.__payClicks = 0;
    document.querySelector('#pay')
        .addEventListener('click', () => { window.__payClicks += 1; });
}"""

# Runs inside the side panel (an extension page with chrome.* APIs).
DIRECT_EXECUTE_JS = """async ({tabId, grant}) => {
    await chrome.scripting.executeScript({target: {tabId}, files: ['src/content/content.js']});
    const send = (m) => chrome.tabs.sendMessage(tabId, m);
    const {snapshot} = await send({cmd: 'snapshot'});
    const pay = snapshot.elements.find((e) => e.text === 'Pay Now');
    const results = [];
    if (grant) {
        await send({cmd: 'grant', nonce: 'g1', elementId: pay.id, snapshotId: snapshot.snapshotId,
                    actionType: grant.actionType, ttlMs: grant.ttlMs});
        await new Promise((r) => setTimeout(r, grant.waitMs || 0));
    }
    for (let i = 0; i < (grant?.attempts || 1); i++) {
        results.push(await send({cmd: 'execute', snapshotId: snapshot.snapshotId,
                                 action: {type: 'click', element_id: pay.id}, grant: grant ? 'g1' : null}));
    }
    return results;
}"""


@pytest.fixture(scope="module")
def extension_context(tmp_path_factory):
    # Grant the local test origin up front: automation cannot click Chrome's
    # runtime permission prompt that real users see.
    ext_dir = tmp_path_factory.mktemp("ext") / "extension"
    shutil.copytree(EXTENSION_SRC, ext_dir, ignore=shutil.ignore_patterns("tests", "node_modules"))
    manifest_path = ext_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["host_permissions"].append("http://127.0.0.1/*")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            str(tmp_path_factory.mktemp("profile")),
            channel="chromium",  # new headless mode, which supports extensions
            headless=True,
            args=[
                f"--disable-extensions-except={ext_dir}",
                f"--load-extension={ext_dir}",
            ],
        )
        try:
            worker = context.service_workers[0] if context.service_workers else context.wait_for_event("serviceworker")
            extension_id = worker.url.split("/")[2]
            yield context, extension_id
        finally:
            context.close()


@pytest.fixture
def ui(extension_context, testlab_server):
    """Opens a testlab page plus a side panel pinned to it; collects console errors."""
    context, extension_id = extension_context
    opened, errors = [], []

    def open_page(page_name="checkout.html"):
        shop = context.new_page()
        shop.goto(f"{testlab_server}/{page_name}")
        if page_name == "checkout.html":
            shop.evaluate(TRACK_PAY_CLICKS_JS)
        panel = context.new_page()
        panel.on("console", lambda m: m.type == "error" and errors.append(m.text))
        panel.on("pageerror", lambda e: errors.append(str(e)))
        panel.goto(f"chrome-extension://{extension_id}/src/sidepanel/panel.html")
        # Default settings and an empty profile/session for each test.
        panel.evaluate("() => Promise.all([chrome.storage.local.clear(), chrome.storage.session.clear()])")
        tab_id = panel.evaluate("async (url) => (await chrome.tabs.query({url})).at(-1).id", f"{testlab_server}/{page_name}")
        panel.goto(f"chrome-extension://{extension_id}/src/sidepanel/panel.html?tab={tab_id}")
        panel.wait_for_selector("#firewall-status")
        opened.extend([shop, panel])
        return shop, panel, tab_id

    yield open_page
    for page in opened:
        page.close()
    assert errors == [], f"Side panel console errors: {errors}"


def _run_until_approval(panel, task="Complete the checkout and pay"):
    panel.click("#nav-agent")
    panel.fill("#task", task)
    panel.click("#run")
    panel.wait_for_selector("dialog#approval[open]", timeout=15000)


def test_deny_executes_nothing_and_ai_never_sees_real_data(ui):
    shop, panel, _ = ui()
    _run_until_approval(panel)

    dialog = panel.text_content("dialog#approval")
    assert "Pay Now" in dialog and "Critical · financial transaction" in dialog
    panel.click("#dialog-deny")
    panel.wait_for_selector("#status.bad")
    assert "denied" in panel.text_content("#status")
    assert shop.evaluate("window.__payClicks") == 0
    assert shop.input_value("#card") == REAL_CARD  # the page keeps its real data

    # Lifecycle shows the denial and that execution never happened.
    assert "blocked" in panel.get_attribute("[data-stage=approve]", "class")
    assert "idle" in panel.get_attribute("[data-stage=execute]", "class")

    # Neither the scanner nor the AI payload ever shows a real value.
    panel.click("#nav-scanner")
    shown = panel.text_content("#view-scanner") + panel.text_content("#ai-payload")
    for real in REAL_VALUES:
        assert real not in shown, real


def test_approve_once_allows_exactly_one_payment_click(ui):
    shop, panel, _ = ui()
    _run_until_approval(panel)
    panel.click("#dialog-approve")
    panel.wait_for_selector("#status.ok", timeout=15000)
    assert shop.evaluate("window.__payClicks") == 1

    panel.click("#nav-approvals")
    assert "Approved once" in panel.text_content("#approval-history")

    panel.click("#nav-ledger")
    panel.click("#verify")
    panel.wait_for_selector("#ledger-status .verdict.ok")
    ledger = panel.text_content("#ledger")
    assert "human_approval" in ledger and REAL_CARD not in ledger

    # Event-type filter narrows the list to matching entries only.
    panel.select_option("#ledger-type", "human_approval")
    entries = panel.locator("#ledger .ledger-entry strong").all_text_contents()
    assert entries and set(entries) == {"human_approval"}


@pytest.mark.parametrize("grant, expected_error, expected_clicks", [
    (None, "This action requires your approval.", 0),
    ({"actionType": "click", "ttlMs": 1, "waitMs": 50}, "Your approval has expired. Ask again.", 0),
    ({"actionType": "type", "ttlMs": 30000}, "This action requires your approval.", 0),
])
def test_page_side_executor_rejects_missing_expired_or_mismatched_grants(ui, grant, expected_error, expected_clicks):
    shop, panel, tab_id = ui()
    [result] = panel.evaluate(DIRECT_EXECUTE_JS, {"tabId": tab_id, "grant": grant})
    assert result == {"ok": False, "error": expected_error}
    assert shop.evaluate("window.__payClicks") == expected_clicks


def test_grant_is_single_use(ui):
    shop, panel, tab_id = ui()
    first, second = panel.evaluate(DIRECT_EXECUTE_JS, {"tabId": tab_id, "grant": {"actionType": "click", "ttlMs": 30000, "attempts": 2}})
    assert first == {"ok": True}
    assert second == {"ok": False, "error": "This action requires your approval."}
    assert shop.evaluate("window.__payClicks") == 1


def test_firewall_off_sends_nothing_and_shows_on_toolbar(ui):
    shop, panel, _ = ui()
    panel.click("#firewall-toggle")
    panel.wait_for_selector("#firewall-status:text('FIREWALL INACTIVE')")
    assert panel.evaluate("() => chrome.action.getBadgeText({})") == "OFF"

    panel.click("#nav-agent")
    panel.fill("#task", "Complete the checkout and pay")
    panel.click("#run")
    panel.wait_for_selector("#status.bad")
    assert "nothing" in panel.text_content("#status").lower()
    assert shop.evaluate("window.__payClicks") == 0
    assert not panel.is_visible("dialog#approval[open]")

    panel.click("#nav-overview")
    panel.click("#firewall-toggle")
    panel.wait_for_selector("#firewall-status:text('FIREWALL ACTIVE')")
    assert panel.evaluate("() => chrome.action.getBadgeText({})") == ""


def test_scanner_quarantines_injections_on_support_page(ui):
    _, panel, _ = ui("support.html")
    panel.click("#nav-scanner")
    panel.click("#scan-button")
    panel.wait_for_selector("#protect-banner.ok")
    text = panel.text_content("#compare-list")
    for real in ["john.doe@example.com", "+91 9876543210", "+91 98765 43210", "9876543210"]:
        assert real not in text, real
    assert text.count("Quarantined") == 2

    panel.click("#nav-threats")
    injections = panel.text_content("#injection-list")
    assert "Hidden text" in injections and "Visible text" in injections
    assert "Reached the AI" not in injections.replace("Never reached the AI", "")


def test_strict_redaction_setting_changes_what_the_ai_sees(ui):
    _, panel, _ = ui()
    panel.click("#nav-settings")
    panel.click("label[for=set-strict]")
    panel.click("#nav-scanner")
    panel.click("#scan-button")
    panel.wait_for_selector("#protect-banner.ok")
    assert "[REDACTED:CARD]" in panel.text_content("#ai-payload")


def test_self_test_button_reports_evidence(ui):
    _, panel, _ = ui()
    panel.click("#nav-validation")
    panel.click("#run-selftest")
    verdict = panel.text_content("#selftest-verdict")
    assert "checks passed" in verdict
    assert panel.locator("#selftest-results .evidence li.ok").count() == panel.locator("#selftest-results .evidence li").count() >= 10


def test_all_five_ps004_scenarios(ui, testlab_server):
    _, panel, _ = ui()
    panel.click("#nav-testlab")
    panel.fill("#testlab-url", testlab_server)
    panel.press("#testlab-url", "Tab")
    panel.click("#run-all")
    panel.wait_for_function(
        "() => !document.querySelector('#run-all').disabled"
        " && document.querySelectorAll('[id$=-result] .check-list, [id$=-result] .verdict').length === 5",
        timeout=90000,
    )
    verdicts = {
        s: panel.text_content(f"#scenario-{s} .scenario-head .chip")
        for s in ["checkout", "login", "support", "video", "dev"]
    }
    assert verdicts == {"checkout": "PASS", "login": "PASS", "support": "PASS", "video": "PARTIAL", "dev": "PASS"}
    # Partial means only unsupported checks remain, never a failure.
    assert panel.locator("#scenario-video .check.fail").count() == 0
    assert panel.locator("#scenario-video .check.unsupported").count() == 2


def test_multi_page_task_follows_link_and_still_asks_before_paying(ui, testlab_server):
    """Regression: the content script must be re-attached after navigation."""
    shop, panel, _ = ui("catalog.html")
    _run_until_approval(panel, task="Go to the cart and pay")

    assert shop.url.endswith("/checkout.html"), "agent did not navigate"
    assert "Pay Now" in panel.text_content("dialog#approval")
    shop.evaluate(TRACK_PAY_CLICKS_JS)
    panel.click("#dialog-approve")
    panel.wait_for_selector("#status.ok", timeout=15000)
    assert shop.evaluate("window.__payClicks") == 1


# Runs runAgent inside the side panel with a planner that copies the card it
# was shown (a synthetic one) into a confirmation field, through the real
# loop: sanitize -> policy -> approval -> restore -> page-side executor.
TYPING_RUN_JS = """async ({tabId, approve}) => {
    const { runAgent } = await import('/src/core/orchestrator.js');
    let card = null;
    const seen = [];
    const result = await runAgent({
        tabId, task: 'Confirm my card number',
        agent: (request) => {
            if (request.history.length) return {type: 'done', reason: 'Filled.'};
            const source = request.elements.find((e) => e.label === 'Card number');
            const target = request.elements.find((e) => e.placeholder === 'Re-enter card');
            seen.push(source.value);
            return {type: 'type', element_id: target.id, text: source.value, reason: 'Confirm the card.'};
        },
        ui: { event() {}, requestApproval: async (c) => { card = c; return approve; } },
    });
    return { status: result.status, seen, risk: card?.risk.level, uses: card?.uses };
}"""

ADD_CONFIRM_FIELD_JS = """() => document.querySelector('form').insertAdjacentHTML('beforeend',
    '<label for="card2">Confirm card</label><input id="card2" placeholder="Re-enter card">')"""


@pytest.mark.parametrize("approve", [True, False])
def test_typing_real_card_needs_approval_and_ai_only_sees_synthetic(ui, approve):
    shop, panel, tab_id = ui()
    shop.evaluate(ADD_CONFIRM_FIELD_JS)

    out = panel.evaluate(TYPING_RUN_JS, {"tabId": tab_id, "approve": approve})

    assert out["seen"] and out["seen"][0] != REAL_CARD          # the AI saw a synthetic card
    assert out["risk"] == "critical"
    assert out["uses"][0]["type"] == "CARD" and REAL_CARD not in out["uses"][0]["masked"]
    if approve:
        assert out["status"] == "completed"
        assert shop.input_value("#card2") == REAL_CARD          # real value typed on the page
    else:
        assert out["status"] == "blocked"
        assert shop.input_value("#card2") == ""                 # nothing typed


def _approve_until_done(panel, approvals=2):
    for _ in range(approvals):
        panel.wait_for_selector("dialog#approval[open]", timeout=15000)
        panel.click("#dialog-approve")
    panel.wait_for_selector("#status.ok", timeout=15000)


def test_agent_signs_in_with_your_details_without_the_ai_seeing_them(ui):
    real = {"email": "priya.real@corp.test", "password": "Real-Pa55word!"}
    shop, panel, _ = ui("signin.html")

    panel.click("#nav-settings")
    for key, value in real.items():
        panel.fill(f"#profile-{key}", value)
        panel.press(f"#profile-{key}", "Tab")
        panel.wait_for_selector(f"label:has(#profile-{key}) .chip-ok")

    panel.click("#nav-agent")
    panel.fill("#task", "Sign in to my account")
    panel.click("#run")
    _approve_until_done(panel)  # password entry, then form submission

    assert shop.evaluate("window.__submitted") == real
    assert shop.is_visible("#result")

    # Nothing the AI received, and nothing in the ledger, contains the real values.
    panel.click("#nav-scanner")
    payload = panel.text_content("#ai-payload")
    panel.click("#nav-ledger")
    ledger = panel.text_content("#ledger")
    panel.click("#nav-settings")
    settings_text = panel.text_content("#view-settings")
    for value in real.values():
        assert value not in payload and value not in ledger and value not in settings_text, value


def test_agent_registers_with_the_synthetic_identity(ui):
    shop, panel, _ = ui("register.html")
    identity = panel.evaluate("async () => (await chrome.storage.session.get('syntheticIdentity')).syntheticIdentity")

    panel.click("#nav-agent")
    panel.fill("#task", "Create an account")
    panel.click("#run")
    _approve_until_done(panel)

    submitted = shop.evaluate("window.__submitted")
    assert submitted == {
        "name": identity["full_name"], "email": identity["email"], "phone": identity["phone"],
        "address": identity["address"], "password": identity["password"],
    }
    assert identity["email"].endswith("@example.com")


def test_page_side_executor_refuses_password_typing_without_a_grant(ui):
    """Defense in depth: even a direct message cannot type a password unapproved."""
    shop, panel, tab_id = ui("signin.html")
    result = panel.evaluate(
        """async (tabId) => {
            await chrome.scripting.executeScript({target: {tabId}, files: ['src/content/content.js']});
            const {snapshot} = await chrome.tabs.sendMessage(tabId, {cmd: 'snapshot'});
            const pw = snapshot.elements.find((e) => e.type === 'password');
            return chrome.tabs.sendMessage(tabId, {cmd: 'execute', snapshotId: snapshot.snapshotId,
                action: {type: 'type', element_id: pw.id, text: 'stolen-guess'}, grant: null});
        }""",
        tab_id,
    )
    assert result == {"ok": False, "error": "This action requires your approval."}
    assert shop.input_value("#password") == ""
