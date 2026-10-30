// Connects the side-panel views to the real PrivacyLens core and Chrome APIs.
// The UI never re-implements security decisions: it calls the same
// scanPage/runAgent/validateOutgoing code the tests exercise, and every
// page action still goes through the page-side executor's own checks.

import { testGeminiConnection } from "../core/agent.js";
import { AuditLedger } from "../core/audit.js";
import {
  DEFAULT_SETTINGS, firewallSelfTest, protectionBlocker, runAgent, scanPage, scanSummary, sendToTab,
} from "../core/orchestrator.js";
import { SCENARIOS, evaluateScan, verdictOf } from "../core/scenarios.js";
import { DEFAULT_UI_SETTINGS } from "./store.js";

const MAX_ACTIVITY = 200;

function originPattern(url) {
  try {
    const u = new URL(url);
    return ["http:", "https:"].includes(u.protocol) ? `${u.protocol}//${u.hostname}/*` : null;
  } catch {
    return null;
  }
}

const hostOf = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
};

export function createController(store, { pinnedTabId = null } = {}) {
  const S = store.state;
  const ledger = new AuditLedger();
  let abort = null;
  let approvalResolver = null;
  let testTabId = null;

  const coreSettings = () => {
    const s = S.settings;
    return {
      ...DEFAULT_SETTINGS,
      firewallEnabled: s.firewallEnabled,
      detectionEnabled: s.detectionEnabled,
      injectionProtection: s.injectionProtection,
      invisibleFilter: s.invisibleFilter,
      redactTypes: s.redactTypes,
      localOnly: s.localOnly,
    };
  };

  function activity(text, tone = "", kind = "info") {
    const entry = { at: new Date().toISOString(), text, tone, kind };
    store.set({ activity: [entry, ...S.activity].slice(0, MAX_ACTIVITY) });
  }

  async function log(event, detail) {
    await ledger.append(event, detail);
    store.set({ ledger: { entries: [...ledger.entries], verification: null } });
  }

  // --- Settings -------------------------------------------------------------

  async function loadSettings() {
    const { settings = {} } = await chrome.storage.local.get("settings");
    const { apiKey } = await chrome.storage.session.get("apiKey");
    store.set({ settings: { ...DEFAULT_UI_SETTINGS, ...settings }, apiKeySet: Boolean(apiKey) });
  }

  async function updateSettings(patch) {
    const settings = { ...S.settings, ...patch };
    store.set({ settings });
    await chrome.storage.local.set({ settings }); // non-secret settings only
    for (const [key, value] of Object.entries(patch)) {
      if (["firewallEnabled", "detectionEnabled", "injectionProtection", "invisibleFilter", "localOnly"].includes(key)) {
        await log("setting_changed", { key, value });
        activity(`${key} turned ${value ? "on" : "off"}`, value ? "ok" : "warn", "settings");
      }
    }
    if ("overlay" in patch) await setOverlay(patch.overlay);
  }

  async function setApiKey(key) {
    // Memory-only storage: cleared when the browser closes, never written to disk.
    if (key) await chrome.storage.session.set({ apiKey: key });
    else await chrome.storage.session.remove("apiKey");
    store.set({ apiKeySet: Boolean(key), gemini: null });
  }

  async function testConnection() {
    const { apiKey } = await chrome.storage.session.get("apiKey");
    store.set({ gemini: { ok: null, message: "Testing…", at: null } });
    const result = await testGeminiConnection({ apiKey, model: S.settings.model });
    store.set({ gemini: { ...result, at: new Date().toISOString() } });
    activity(`Gemini connection: ${result.message}`, result.ok ? "ok" : "bad", "agent");
  }

  // --- Tab, access and monitoring --------------------------------------------

  async function activeTab() {
    if (pinnedTabId != null) return chrome.tabs.get(pinnedTabId);
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab;
  }

  async function refreshTab() {
    const tab = await activeTab().catch(() => null);
    const pattern = tab?.url ? originPattern(tab.url) : null;
    const access = pattern ? await chrome.permissions.contains({ origins: [pattern] }) : false;
    let monitoring = null;
    if (access) {
      try {
        monitoring = await chrome.tabs.sendMessage(tab.id, { cmd: "ping" }, { frameId: 0 });
      } catch {
        monitoring = null; // content script not attached yet
      }
    }
    store.set({
      tab: {
        id: tab?.id ?? null, url: tab?.url || "", web: Boolean(pattern), access,
        origin: pattern ? new URL(tab.url).origin : "", host: hostOf(tab?.url), monitoring,
      },
    });
  }

  async function requestAccess(url = S.tab.url) {
    const pattern = originPattern(url);
    if (!pattern) return false;
    if (await chrome.permissions.contains({ origins: [pattern] })) return true;
    const granted = await chrome.permissions.request({ origins: [pattern] });
    await log("site_access", { granted });
    await refreshTab();
    return granted;
  }

  async function grantedOrigins() {
    const { origins = [] } = await chrome.permissions.getAll();
    return origins.filter((o) => !o.includes("generativelanguage.googleapis.com"));
  }

  async function revokeOrigin(origin) {
    const removed = await chrome.permissions.remove({ origins: [origin] });
    await log("site_access_revoked", { removed });
    activity(removed ? `Access revoked for ${origin}` : `Could not revoke ${origin} (granted at install)`, removed ? "ok" : "warn", "settings");
    await refreshTab();
    return removed;
  }

  async function setSiteBlocked(host, blocked) {
    const list = new Set(S.settings.blockedSites);
    if (blocked) list.add(host);
    else list.delete(host);
    await updateSettings({ blockedSites: [...list] });
    await log("never_send_list_changed", { blocked, entries: list.size });
  }

  async function ensureContentScript(tabId) {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["src/content/content.js"] });
  }

  // Common pre-flight for anything that reads the page.
  async function preparePage() {
    await refreshTab();
    if (!S.tab.web) throw new Error("PrivacyLens works on http(s) pages only.");
    if (S.settings.blockedSites.includes(S.tab.host)) throw new Error("This site is on your never-send list.");
    if (!(await requestAccess())) throw new Error("Access to this site was not granted.");
    await ensureContentScript(S.tab.id);
    return S.tab.id;
  }

  async function setOverlay(visible) {
    if (!S.tab.access || S.tab.id == null) return;
    try {
      await ensureContentScript(S.tab.id);
      await chrome.tabs.sendMessage(S.tab.id, { cmd: "overlayVisible", visible }, { frameId: 0 });
    } catch {
      // Page not injectable right now; applied on the next scan.
    }
    await refreshTab();
  }

  // --- Scanning ---------------------------------------------------------------

  function recordScan(summary, source) {
    const prev = S.riskHistory.at(-1);
    const counts = Object.fromEntries(summary.risk.categories.map((c) => [c.type, c.count]));
    const changes = [];
    for (const type of new Set([...Object.keys(counts), ...Object.keys(prev?.counts || {})])) {
      const delta = (counts[type] || 0) - (prev?.counts?.[type] || 0);
      if (delta) changes.push(`${delta > 0 ? "+" : ""}${delta} ${type}`);
    }
    const entry = {
      at: new Date().toISOString(), total: summary.risk.total, counts, host: S.tab.host,
      delta: prev ? summary.risk.total - prev.total : null,
      why: !prev ? "First scan of this session." : changes.length ? `Detected categories changed: ${changes.join(", ")}.` : "Same categories as the previous scan.",
    };
    const stats = { ...S.stats, inspected: S.stats.inspected + 1, honeytokenChecks: S.stats.honeytokenChecks + 1 };
    if (summary.honeytokenOk) stats.honeytokenPassed += 1;
    if (!summary.egress.ok) stats.blocked += 1;
    store.set({ scan: { ...summary, at: entry.at, source }, riskHistory: [...S.riskHistory, entry].slice(-20), stats });
  }

  async function scanCurrentPage() {
    const blocker = protectionBlocker(coreSettings());
    if (blocker) {
      activity(blocker, "bad", "scan");
      return { ok: false, message: blocker };
    }
    try {
      const tabId = await preparePage();
      const { snapshot } = await sendToTab(tabId, { cmd: "snapshot" });
      const scan = scanPage(snapshot, { settings: coreSettings() });
      const summary = scanSummary(scan);
      recordScan(summary, "scan");
      await sendToTab(tabId, {
        cmd: "overlay",
        items: summary.rows.filter((r) => !r.hidden).map((r) => ({ id: r.id, type: r.type })),
        quarantined: summary.injections.filter((i) => i.quarantined && !i.hidden).map((i) => i.id),
      });
      await sendToTab(tabId, { cmd: "overlayVisible", visible: S.settings.overlay });
      await log("page_scanned", {
        risk: summary.risk.total, protectedValues: summary.protectedValues,
        injections: summary.injections.length, egressOk: summary.egress.ok, honeytokenOk: summary.honeytokenOk,
      });
      activity(`Scanned ${S.tab.host}: ${summary.rows.length} sensitive value(s) protected, ${summary.injections.length} injection(s)`, summary.egress.ok ? "ok" : "bad", "scan");
      await refreshTab();
      return { ok: true };
    } catch (err) {
      activity(`Scan failed: ${err.message}`, "bad", "scan");
      return { ok: false, message: err.message };
    }
  }

  // --- Agent ------------------------------------------------------------------

  function requestApproval(card) {
    const pending = { ...card, at: new Date().toISOString() };
    store.set({ approvals: { ...S.approvals, pending } });
    activity(`Approval needed: ${card.action} "${card.target}" (${card.risk.label})`, "warn", "approval");
    return new Promise((resolve) => {
      approvalResolver = (approved) => {
        approvalResolver = null;
        const decided = { ...pending, decided: new Date().toISOString(), approved };
        store.set({ approvals: { pending: null, history: [decided, ...S.approvals.history] } });
        activity(`${approved ? "Approved once" : "Denied"}: ${card.action} "${card.target}"`, approved ? "warn" : "ok", "approval");
        resolve(approved);
      };
    });
  }

  function resolveApproval(approved) {
    approvalResolver?.(approved);
  }

  const uiBridge = {
    event(kind, data) {
      if (kind === "selftest") store.set({ selfTest: data });
      else if (kind === "stage") {
        // Each step starts a fresh lifecycle, so a previous step's "Execute ✓"
        // never shows next to this step's denial.
        const base = data.stage === "observe" && data.state === "active"
          ? Object.fromEntries(Object.keys(S.agent.stages).map((k) => [k, { state: "idle", detail: "" }]))
          : S.agent.stages;
        const stages = { ...base, [data.stage]: { state: data.state, detail: data.stage === "observe" && data.state === "active" ? `Step ${data.step + 1}: reading the page` : data.detail } };
        store.set({ agent: { ...S.agent, stages } });
      } else if (kind === "scan") {
        const { step, source, ...summary } = data;
        recordScan(summary, `agent step ${step + 1}`);
      } else if (kind === "egress") {
        if (data.kind === "http") {
          const stats = { ...S.stats, inspected: S.stats.inspected + 1, blocked: S.stats.blocked + (data.ok ? 0 : 1) };
          store.set({ stats });
        }
        activity(data.ok ? `Egress firewall (${data.kind}): request clean` : `Egress firewall BLOCKED (${data.kind}): ${data.reasons[0]}`, data.ok ? "ok" : "bad", "egress");
      } else if (kind === "action") {
        const entry = { step: data.step, ...data.action, decision: data.decision, reason: data.reason || data.action.reason, exec: null };
        store.set({ agent: { ...S.agent, actions: [...S.agent.actions, entry] } });
        activity(`Step ${data.step + 1}: agent proposes ${data.action.type}${data.action.element_id ? ` ${data.action.element_id}` : ""}`, "", "agent");
      } else if (kind === "executed") {
        const actions = S.agent.actions.map((a) => (a.step === data.step ? { ...a, exec: data.ok ? "executed" : `refused: ${data.error}` } : a));
        store.set({ agent: { ...S.agent, actions } });
      } else if (kind === "finished") {
        const tone = data.status === "completed" ? "ok" : data.status === "stopped" ? "warn" : "bad";
        store.set({ agent: { ...S.agent, status: { text: data.message, tone } } });
        activity(`Run finished (${data.status}): ${data.message}`, tone, "agent");
      }
      store.set({ ledger: { entries: [...ledger.entries], verification: null } });
    },
    requestApproval,
  };

  async function runTask(task) {
    if (S.agent.running) return;
    store.resetStages();
    const settings = coreSettings();
    const blocker = protectionBlocker(settings);
    const status = (text, tone = "bad") => store.set({ agent: { ...S.agent, status: { text, tone } } });
    if (blocker) return status(blocker);
    if (!task.trim()) return status("Enter a task first.");
    const mode = S.settings.mode;
    const { apiKey } = await chrome.storage.session.get("apiKey");
    if (mode === "gemini" && settings.localOnly) return status("Local-only mode is on: switch to the offline agent or turn local-only off in Settings.");
    if (mode === "gemini" && !apiKey) return status("Gemini is not configured: add an API key in Settings, or use the offline agent.");

    let tabId;
    try {
      tabId = await preparePage();
      await sendToTab(tabId, { cmd: "overlayVisible", visible: S.settings.overlay });
    } catch (err) {
      return status(err.message);
    }

    abort = new AbortController();
    store.set({ agent: { ...S.agent, running: true, task, status: { text: "Running…", tone: "" } } });
    await log("run_started", { mode, maxSteps: S.settings.maxSteps ?? 6 });
    try {
      await runAgent({
        tabId, task, mode, apiKey, model: S.settings.model,
        maxSteps: Math.min(10, Math.max(1, Number(S.settings.maxSteps) || 6)),
        signal: abort.signal, ui: uiBridge, ledger, settings,
      });
    } catch (err) {
      status(`Stopped: ${err.message}`);
      activity(`Run error: ${err.message}`, "bad", "agent");
    } finally {
      abort = null;
      store.set({ agent: { ...S.agent, running: false }, ledger: { entries: [...ledger.entries], verification: null } });
      await refreshTab();
    }
  }

  function stop() {
    abort?.abort();
    resolveApproval(false);
  }

  // --- Validation ---------------------------------------------------------------

  async function runSelfTest() {
    const result = firewallSelfTest();
    store.set({ selfTest: result });
    await log("firewall_self_test", { ok: result.ok, checks: result.checks });
    activity(`Firewall self-test ${result.ok ? "passed" : "FAILED"} (${result.evidence.filter((e) => e.passed).length}/${result.evidence.length})`, result.ok ? "ok" : "bad", "validation");
    return result;
  }

  function networkPolicy() {
    const csp = chrome.runtime.getManifest().content_security_policy?.extension_pages || "";
    const connect = /connect-src ([^;]+)/.exec(csp)?.[1]?.trim() || "(not restricted)";
    return { csp, connect };
  }

  // --- Ledger -----------------------------------------------------------------

  async function verifyLedger() {
    const verification = await ledger.verify();
    store.set({ ledger: { entries: [...ledger.entries], verification: { ...verification, at: new Date().toISOString() } } });
    activity(verification.ok ? `Ledger verified (${ledger.entries.length} entries)` : `Ledger BROKEN at entry #${verification.brokenAt}`, verification.ok ? "ok" : "bad", "ledger");
    return verification;
  }

  async function exportReceipt() {
    const receipt = await ledger.receipt();
    const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `privacylens-receipt-${Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    activity("Privacy receipt exported", "ok", "ledger");
  }

  async function clearLedger() {
    ledger.entries.length = 0;
    await log("ledger_cleared", {});
    activity("Ledger cleared; a new hash chain was started", "warn", "ledger");
  }

  // --- Test Lab -------------------------------------------------------------------

  async function openTestTab(url) {
    if (testTabId != null) {
      try {
        await chrome.tabs.update(testTabId, { url });
      } catch {
        testTabId = null;
      }
    }
    if (testTabId == null) testTabId = (await chrome.tabs.create({ url, active: false })).id;
    // Wait for *this* navigation: a reused tab still reports the previous
    // page as "complete" until the new load starts. An unreachable server
    // ends on Chrome's error page, whose URL differs, and fails below.
    for (let i = 0; i < 100; i++) {
      const tab = await chrome.tabs.get(testTabId);
      if (tab.status === "complete" && tab.url === url) return tab;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`Test page did not load. Is the test server running at ${new URL(url).origin}? Start it with: python testlab/serve.py`);
  }

  async function runScenario(id) {
    const scenario = SCENARIOS.find((s) => s.id === id);
    const base = S.settings.testlabBaseUrl.replace(/\/+$/, "");
    const url = `${base}/${scenario.page}`;
    store.set({ testlab: { ...S.testlab, running: id } });
    const done = (result) => {
      store.set({ testlab: { running: null, results: { ...S.testlab.results, [id]: { ...result, at: new Date().toISOString() } } } });
      activity(`Test Lab · ${scenario.title}: ${result.verdict.toUpperCase()}`, result.verdict === "pass" ? "ok" : result.verdict === "partial" ? "warn" : "bad", "testlab");
      return result;
    };
    try {
      if (!(await requestAccess(url))) throw new Error(`Access to ${new URL(url).origin} was not granted.`);
      const tab = await openTestTab(url);
      try {
        await ensureContentScript(tab.id);
      } catch {
        throw new Error(`Test server not reachable at ${base}. Start it with: python testlab/serve.py`);
      }
      const { snapshot } = await sendToTab(tab.id, { cmd: "snapshot" });
      // Scenarios always run with the secure defaults, regardless of toggles.
      const scan = scanPage(snapshot, { settings: DEFAULT_SETTINGS, task: scenario.task });
      const checks = evaluateScan(scenario, snapshot, scan);

      if (scenario.dynamic?.includes("payApproval")) checks.push(...(await payApprovalChecks(tab.id, scenario)));

      await sendToTab(tab.id, {
        cmd: "overlay",
        items: scan.sanitized.rows.filter((r) => !r.hidden).map((r) => ({ id: r.id, type: r.type })),
        quarantined: scan.sanitized.injections.filter((i) => i.quarantined && !i.hidden).map((i) => i.id),
      });
      const verdict = verdictOf(checks);
      await log("scenario_run", { scenario: id, verdict, checks: checks.length });
      return done({ verdict, checks, url });
    } catch (err) {
      await log("scenario_run", { scenario: id, verdict: "error" });
      return done({ verdict: "error", checks: [], error: err.message, url });
    }
  }

  // Runs the real agent loop against the checkout page with an automatic
  // "Deny", then proves at the page level that Pay was never clicked.
  async function payApprovalChecks(tabId, scenario) {
    const out = [];
    await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        window.__plTestPayClicks = 0;
        document.querySelector("#pay")?.addEventListener("click", () => { window.__plTestPayClicks += 1; });
      },
    });
    let card = null;
    const result = await runAgent({
      tabId, task: scenario.task, mode: "mock", maxSteps: 4, settings: DEFAULT_SETTINGS, ledger,
      ui: { event() {}, requestApproval: async (c) => { card = c; return false; } },
    });
    out.push({
      name: "Pay click requires human approval",
      expected: "Approval card for \"Pay Now\" with a critical risk rating",
      actual: card ? `Card shown for "${card.target}" (${card.risk.label}); harness denied` : "No approval was requested",
      status: card && card.target === "Pay Now" && card.risk.level === "critical" ? "pass" : "fail",
      evidence: `Run ended: ${result.status} · ${result.message}`,
    });

    const { snapshot } = await sendToTab(tabId, { cmd: "snapshot" });
    const pay = snapshot.elements.find((e) => e.text === "Pay Now");
    let refusal = "";
    try {
      await sendToTab(tabId, { cmd: "execute", snapshotId: snapshot.snapshotId, action: { type: "click", element_id: pay.id }, grant: null });
    } catch (err) {
      refusal = err.message;
    }
    const [{ result: clicks }] = await chrome.scripting.executeScript({ target: { tabId }, func: () => window.__plTestPayClicks });
    out.push({
      name: "Page-side executor refuses Pay without a grant",
      expected: "Refused; Pay button never clicked",
      actual: `${refusal ? `Refused ("${refusal}")` : "EXECUTED"}; Pay clicks on page: ${clicks}`,
      status: refusal && clicks === 0 ? "pass" : "fail",
      evidence: "Direct execute message sent with no grant, bypassing the side panel's own checks",
    });
    return out;
  }

  async function runAllScenarios() {
    for (const s of SCENARIOS) await runScenario(s.id);
  }

  // --- Startup ----------------------------------------------------------------

  async function init() {
    await loadSettings();
    await refreshTab();
    await log("panel_opened", {});
    await runSelfTest();
    chrome.tabs.onActivated.addListener(() => pinnedTabId == null && refreshTab());
    chrome.tabs.onUpdated.addListener((tabId, info) => {
      if (tabId === S.tab.id && info.status === "complete") refreshTab();
    });
    setInterval(() => S.tab.access && refreshTab(), 4000); // monitoring indicator
  }

  return {
    init, refreshTab, requestAccess, grantedOrigins, revokeOrigin, setSiteBlocked,
    updateSettings, setApiKey, testConnection,
    scanCurrentPage, setOverlay, runTask, stop, resolveApproval,
    runSelfTest, networkPolicy,
    verifyLedger, exportReceipt, clearLedger,
    runScenario, runAllScenarios,
    activity,
  };
}
