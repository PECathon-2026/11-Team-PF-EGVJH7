"""Shared fixtures: an isolated testlab HTTP server and Playwright pages.

The testlab server (testlab/serve.py) is started once per test session the
first time any test requests it, and is always terminated at session end.
Unit tests that never ask for it do not pay the startup cost.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright


REPO_ROOT = Path(__file__).resolve().parent.parent
SERVE_SCRIPT = REPO_ROOT / "testlab" / "serve.py"

STARTUP_TIMEOUT_S = 15.0


def _free_port() -> int:
    """Ask the OS for an unused port so a manually started server on 8000
    (or anything else) can never be mistaken for the test instance."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _server_responds(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            return response.status == 200
    except (urllib.error.URLError, ConnectionError, OSError):
        return False


@pytest.fixture(scope="session")
def testlab_server():
    """Run testlab/serve.py in a background process for the whole session."""

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    probe_url = f"{base_url}/checkout.html"

    # The request log goes to a file, not a pipe: an undrained pipe can fill
    # up and stall the server mid-suite.
    log = tempfile.TemporaryFile()
    process = subprocess.Popen(
        [sys.executable, "-u", str(SERVE_SCRIPT)],
        cwd=str(REPO_ROOT),
        stdout=log,
        stderr=subprocess.STDOUT,
        env={
            **os.environ,
            "PRIVACYLENS_TESTLAB_PORT": str(port),
            "PYTHONUNBUFFERED": "1",
        },
    )

    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while not _server_responds(probe_url):
            if process.poll() is not None:
                log.seek(0)
                output = log.read().decode(errors="replace")
                pytest.fail(f"testlab server exited during startup:\n{output}")
            if time.monotonic() > deadline:
                pytest.fail(
                    f"testlab server did not respond within {STARTUP_TIMEOUT_S}s."
                )
            time.sleep(0.1)

        yield base_url

    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()


@pytest.fixture(scope="module")
def browser():
    """Headless Chromium shared by the tests of one module.

    Module scope (not session scope) matters: other test modules start their
    own sync_playwright() instance, and two sync instances cannot be active
    in the same thread at once.
    """

    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch(headless=True)
        try:
            yield chromium
        finally:
            chromium.close()


@pytest.fixture
def page(browser):
    """A fresh browser context per test, so no state leaks between tests."""

    context = browser.new_context(viewport={"width": 1280, "height": 800})
    try:
        yield context.new_page()
    finally:
        context.close()


@pytest.fixture
def checkout_page(page, testlab_server):
    """The local checkout page, loaded from the isolated testlab server."""

    page.goto(f"{testlab_server}/checkout.html", wait_until="domcontentloaded")
    return page
