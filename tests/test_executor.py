
import pytest
from playwright.sync_api import sync_playwright

from contracts.models import Action
from core.browser.executor import execute_action
from core.browser.vault import SecretVault


@pytest.fixture
def browser_page():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content("""
            <!doctype html>
            <html>
              <body>
                <input id="name" data-pl-id="e1" type="text">
                <button id="continue" data-pl-id="e2"
                        onclick="document.body.dataset.clicked='yes'">
                  Continue
                </button>
                <p id="result"></p>
              </body>
            </html>
        """)
        try:
            yield page
        finally:
            browser.close()


def test_executor_types_text(browser_page):
    result = execute_action(
        browser_page,
        Action(type="type", element_id="e1", text="PrivacyLens test"),
        SecretVault(),
    )

    assert result["ok"]
    assert browser_page.locator("#name").input_value() == "PrivacyLens test"


def test_executor_clicks_button(browser_page):
    result = execute_action(
        browser_page,
        Action(type="click", element_id="e2"),
        SecretVault(),
    )

    assert result["ok"]
    assert browser_page.locator("body").get_attribute("data-clicked") == "yes"


def test_executor_rejects_missing_element(browser_page):
    result = execute_action(
        browser_page,
        Action(type="click", element_id="missing"),
        SecretVault(),
    )

    assert not result["ok"]


def test_executor_types_vault_secret_locally(browser_page):
    vault = SecretVault({"TEST_SECRET": "dummy-local-test-value"})

    result = execute_action(
        browser_page,
        Action(
            type="type",
            element_id="e1",
            secret_ref="TEST_SECRET",
        ),
        vault,
    )

    assert result["ok"]
    assert browser_page.locator("#name").input_value() == "dummy-local-test-value"
