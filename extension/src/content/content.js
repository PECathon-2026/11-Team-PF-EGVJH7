// P1 in the page: snapshot, executor and "AI-eye" overlay.
// Injected on demand by the side panel (never on pages you have not chosen).
// Classic script, not a module: content scripts injected via
// chrome.scripting cannot use ES imports.

(() => {
  if (window.__privacyLensLoaded) return;
  window.__privacyLensLoaded = true;

  const INTERACTIVE = "button, input, textarea, select, a, [role='button'], [contenteditable='true']";
  const TEXT_REGIONS = "p, h1, h2, h3, h4, h5, h6, li, blockquote, td, th, dt, dd, svg, [role='img']";
  const MAX_ELEMENTS = 400;
  const MAX_TEXT = 500;

  // Duplicated from src/core/policy.js on purpose: the executor re-checks
  // independently, so an orchestrator bug alone cannot trigger a payment.
  const SENSITIVE_WORDS = [
    "pay", "purchase", "buy", "checkout", "transfer", "delete",
    "remove account", "submit order", "confirm payment", "place order",
    "send money", "withdraw", "sign out", "log out",
  ];
  const RISKY_URL = /(?:^|[^a-z0-9])(?:delete|remove|submit|purchase|buy|transfer|pay|logout|cancel|destroy|withdraw|refund)(?:$|[^a-z0-9])/i;

  let currentSnapshotId = null;
  // nonce -> {elementId, snapshotId, actionType, expiresAt}. Single use,
  // bound to one element and action type, and cleared by every new snapshot.
  const grants = new Map();
  const GRANT_TTL_MAX_MS = 60_000;

  function isVisible(el) {
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) return false;
    if (el.closest("[aria-hidden='true'], [hidden]")) return false;
    if (el.tagName === "INPUT" && el.type === "hidden") return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) return false;
    const docWidth = Math.max(document.documentElement.scrollWidth, innerWidth);
    const docHeight = Math.max(document.documentElement.scrollHeight, innerHeight);
    const x = rect.left + scrollX;
    const y = rect.top + scrollY;
    return x + rect.width > 0 && y + rect.height > 0 && x < docWidth && y < docHeight;
  }

  function labelFor(el) {
    return (el.getAttribute("aria-label") || el.labels?.[0]?.innerText || "").trim().slice(0, MAX_TEXT);
  }

  function isFormSubmit(el) {
    if (el.tagName === "BUTTON") {
      const type = (el.getAttribute("type") || "submit").toLowerCase();
      return type === "submit" && Boolean(el.form);
    }
    return el.tagName === "INPUT" && ["submit", "image"].includes(el.type);
  }

  function snapshot() {
    document.querySelectorAll("[data-pl-id]").forEach((el) => {
      el.removeAttribute("data-pl-id");
      el.removeAttribute("data-pl-snapshot");
    });
    currentSnapshotId = crypto.randomUUID();
    grants.clear();

    const elements = [];
    let index = 0;
    for (const el of document.querySelectorAll(INTERACTIVE)) {
      if (elements.length >= MAX_ELEMENTS) break;
      const id = `e${++index}`;
      el.setAttribute("data-pl-id", id);
      el.setAttribute("data-pl-snapshot", currentSnapshotId);
      const isField = el.matches("input, textarea, select");
      elements.push({
        id,
        tag: el.tagName.toLowerCase(),
        domId: el.id || "",
        role: el.getAttribute("role"),
        type: el.getAttribute("type"),
        name: el.getAttribute("name"),
        label: labelFor(el),
        placeholder: el.getAttribute("placeholder") || "",
        text: isField ? "" : (el.innerText || el.textContent || "").trim().slice(0, MAX_TEXT),
        value: typeof el.value === "string" ? el.value.slice(0, MAX_TEXT) : "",
        attrs: {
          autocomplete: el.getAttribute("autocomplete") || "",
          placeholder: el.getAttribute("placeholder") || "",
          href: el.getAttribute("href") || "",
          disabled: Boolean(el.disabled),
          readonly: Boolean(el.readOnly),
        },
        formSubmit: isFormSubmit(el),
        visible: isVisible(el),
      });
    }

    let textIndex = 0;
    for (const el of document.querySelectorAll(TEXT_REGIONS)) {
      if (elements.length >= MAX_ELEMENTS) break;
      if (el.closest(INTERACTIVE) || el.querySelector(TEXT_REGIONS)) continue; // avoid duplicates
      const text = (el.innerText || el.textContent || "").trim();
      if (!text) continue;
      const id = `t${++textIndex}`;
      el.setAttribute("data-pl-id", id);
      el.setAttribute("data-pl-snapshot", currentSnapshotId);
      elements.push({
        id, tag: el.tagName.toLowerCase(), domId: el.id || "", role: null, type: null, name: null,
        label: "", placeholder: "", value: "", attrs: {}, text: text.slice(0, MAX_TEXT),
        visible: isVisible(el),
      });
    }

    return { url: location.href, title: document.title, snapshotId: currentSnapshotId, elements };
  }

  function luhnCard(text) {
    for (const m of text.matchAll(/(?:\d[ -]?){12,18}\d/g)) {
      const digits = m[0].replace(/\D/g, "");
      let total = 0;
      [...digits].reverse().forEach((ch, i) => {
        let n = Number(ch);
        if (i % 2 === 1 && (n *= 2) > 9) n -= 9;
        total += n;
      });
      if (total % 10 === 0) return true;
    }
    return false;
  }

  function needsGrant(el, action) {
    if (action.type === "click") {
      const description = [el.innerText, el.value, labelFor(el), el.getAttribute("name")]
        .filter(Boolean).join(" ").toLowerCase();
      if (SENSITIVE_WORDS.some((w) => description.includes(w)) || isFormSubmit(el)) return true;
      const href = el.closest("a")?.getAttribute("href");
      if (href && RISKY_URL.test(decodeURIComponent(href))) return true;
    }
    if ((action.type === "type" || action.type === "select") && luhnCard(action.text || "")) return true;
    return false;
  }

  function setNativeValue(el, value) {
    const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype
      : el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function execute({ action, snapshotId, grant }) {
    if (action.type === "scroll") {
      window.scrollBy(0, innerHeight * 0.8);
      return;
    }
    if (action.type === "navigate") {
      const url = new URL(action.url);
      if (!["http:", "https:"].includes(url.protocol)) throw new Error("Navigation must use HTTP(S).");
      location.assign(url.href);
      return;
    }
    if (snapshotId !== currentSnapshotId) throw new Error("Snapshot is stale; take a fresh snapshot.");
    const matches = document.querySelectorAll(`[data-pl-id="${CSS.escape(action.element_id)}"]`);
    if (matches.length !== 1) throw new Error("Element is missing or ambiguous.");
    const el = matches[0];
    if (el.getAttribute("data-pl-snapshot") !== snapshotId) throw new Error("Snapshot is stale.");
    if (!isVisible(el) || el.disabled) throw new Error("Element is hidden or disabled.");

    const g = grant ? grants.get(grant) : null;
    if (grant) grants.delete(grant); // single use, even if the checks below fail
    if (needsGrant(el, action)) {
      if (!g || g.elementId !== action.element_id || g.snapshotId !== snapshotId || g.actionType !== action.type) {
        throw new Error("This action requires your approval.");
      }
      if (Date.now() > g.expiresAt) throw new Error("Your approval has expired. Ask again.");
    }

    el.scrollIntoView({ block: "center" });
    if (action.type === "click") {
      el.click();
    } else if (action.type === "type") {
      if (!el.matches("input, textarea") || el.type === "password" || el.readOnly) {
        throw new Error("Element cannot be typed into.");
      }
      el.focus();
      setNativeValue(el, action.text);
    } else if (action.type === "select") {
      if (el.tagName !== "SELECT" || ![...el.options].some((o) => o.value === action.text)) {
        throw new Error("Option not found.");
      }
      setNativeValue(el, action.text);
    } else {
      throw new Error("Unsupported action.");
    }
  }

  // --- AI-eye overlay --------------------------------------------------------

  let overlayHost = null;
  let overlayItems = { items: [], quarantined: [] };
  let overlayVisible = false;

  function drawOverlay() {
    overlayHost?.remove();
    overlayHost = null;
    if (!overlayVisible) return;

    overlayHost = document.createElement("privacylens-overlay");
    overlayHost.style.cssText = "position:absolute;left:0;top:0;width:0;height:0;z-index:2147483647;pointer-events:none;";
    const root = overlayHost.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      .box{position:absolute;border:2px solid #7c5cff;background:rgba(124,92,255,.12);border-radius:4px;box-sizing:border-box}
      .box.q{border-color:#e5484d;background:rgba(229,72,77,.15)}
      .tag{position:absolute;top:-18px;left:-2px;font:600 10px/16px system-ui,sans-serif;color:#fff;background:#7c5cff;padding:0 6px;border-radius:4px 4px 0 0;white-space:nowrap}
      .q .tag{background:#e5484d}`;
    root.append(style);

    const add = (id, label, quarantined) => {
      const el = document.querySelector(`[data-pl-id="${CSS.escape(id)}"]`);
      if (!el) return;
      const r = el.getBoundingClientRect();
      const box = document.createElement("div");
      box.className = quarantined ? "box q" : "box";
      box.style.cssText = `left:${r.left + scrollX - 2}px;top:${r.top + scrollY - 2}px;width:${r.width + 4}px;height:${r.height + 4}px`;
      const tag = document.createElement("div");
      tag.className = "tag";
      tag.textContent = label;
      box.append(tag);
      root.append(box);
    };
    const types = new Map();
    for (const { id, type } of overlayItems.items) types.set(id, [...(types.get(id) || []), type]);
    for (const [id, list] of types) add(id, `PROTECTED · ${[...new Set(list)].join(" + ")}`, false);
    for (const id of overlayItems.quarantined) add(id, "QUARANTINED · PROMPT INJECTION", true);
    document.documentElement.append(overlayHost);
  }

  addEventListener("resize", () => overlayVisible && drawOverlay());

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return false;
    try {
      switch (msg.cmd) {
        case "ping":
          sendResponse({
            ok: true,
            overlayVisible,
            protectedCount: overlayItems.items.length,
            quarantinedCount: overlayItems.quarantined.length,
            snapshotId: currentSnapshotId,
          });
          break;
        case "snapshot":
          sendResponse({ ok: true, snapshot: snapshot() });
          break;
        case "grant": {
          const ttl = Math.min(GRANT_TTL_MAX_MS, Math.max(1, Number(msg.ttlMs) || 30_000));
          grants.set(msg.nonce, {
            elementId: msg.elementId, snapshotId: msg.snapshotId,
            actionType: msg.actionType, expiresAt: Date.now() + ttl,
          });
          sendResponse({ ok: true });
          break;
        }
        case "execute":
          execute(msg);
          sendResponse({ ok: true });
          break;
        case "overlay":
          overlayItems = { items: msg.items || [], quarantined: msg.quarantined || [] };
          drawOverlay();
          sendResponse({ ok: true });
          break;
        case "overlayVisible":
          overlayVisible = Boolean(msg.visible);
          drawOverlay();
          sendResponse({ ok: true });
          break;
        default:
          sendResponse({ ok: false, error: "Unknown command." });
      }
    } catch (err) {
      sendResponse({ ok: false, error: String(err.message || err) });
    }
    return false;
  });
})();
