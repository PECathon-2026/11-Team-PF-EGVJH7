import { h, icon, setChildren } from "./ui.js";
import { createStore } from "./store.js";
import { createController } from "./controller.js";
import { overviewView } from "./views/overview.js";
import { scannerView } from "./views/scanner.js";
import { overlayView } from "./views/overlay.js";
import { agentView } from "./views/agent.js";
import { approvalsView, approvalCard } from "./views/approvals.js";
import { threatsView } from "./views/threats.js";
import { validationView } from "./views/validation.js";
import { ledgerView } from "./views/ledger.js";
import { testlabView } from "./views/testlab.js";
import { settingsView } from "./views/settings.js";

// ?tab=<id> pins the panel to one tab (used by the automated E2E tests).
const params = new URLSearchParams(location.search);
const pinnedTabId = params.has("tab") ? Number(params.get("tab")) : null;

const store = createStore();
const ctl = createController(store, { pinnedTabId });

const SECTIONS = [
  { id: "overview", label: "Overview", icon: "home", create: overviewView },
  { id: "scanner", label: "Scanner", icon: "scan", create: scannerView },
  { id: "overlay", label: "AI-Eye", icon: "eye", create: overlayView },
  { id: "agent", label: "Agent", icon: "bot", create: agentView },
  { id: "approvals", label: "Approvals", icon: "hand", create: approvalsView },
  { id: "threats", label: "Threats", icon: "alert", create: threatsView },
  { id: "validation", label: "Validation", icon: "shieldCheck", create: validationView },
  { id: "ledger", label: "Ledger", icon: "list", create: ledgerView },
  { id: "testlab", label: "Test Lab", icon: "flask", create: testlabView },
  { id: "settings", label: "Settings", icon: "settings", create: settingsView },
];

const views = new Map();
const main = document.getElementById("main");
const nav = document.getElementById("nav");
const dialog = document.getElementById("approval");
const banner = document.getElementById("approval-banner");
const pill = document.getElementById("firewall-pill");

for (const section of SECTIONS) {
  const view = section.create(store, ctl);
  view.root.id = `view-${section.id}`;
  view.root.hidden = true;
  view.root.setAttribute("role", "tabpanel");
  main.append(view.root);
  views.set(section.id, view);
  nav.append(h("button", {
    class: "nav-item", role: "tab", id: `nav-${section.id}`, dataset: { view: section.id },
    "aria-controls": `view-${section.id}`, onclick: () => store.set({ view: section.id }),
  }, icon(section.icon, 16), h("span", { text: section.label }), h("span", { class: "nav-badge", hidden: true })));
}

let shownPending = null;
let lastView = null;

function render(S) {
  // Theme
  const theme = S.settings.theme === "system"
    ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
    : S.settings.theme;
  document.documentElement.dataset.theme = theme;

  // Header
  const on = S.settings.firewallEnabled;
  pill.textContent = on ? "FIREWALL ACTIVE" : "FIREWALL INACTIVE";
  pill.className = `pill ${on ? "pill-ok" : "pill-bad"}`;

  // Navigation
  for (const button of nav.children) {
    const active = button.dataset.view === S.view;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
    const badge = button.querySelector(".nav-badge");
    if (button.dataset.view === "approvals") {
      badge.hidden = !S.approvals.pending;
      badge.textContent = "1";
    }
  }
  if (S.view !== lastView) {
    for (const [id, view] of views) view.root.hidden = id !== S.view;
    nav.querySelector(".active")?.scrollIntoView({ block: "nearest", inline: "nearest" });
    main.scrollTop = 0;
    lastView = S.view;
  }
  views.get(S.view).update(S);

  // Approvals: banner + modal dialog, both resolving the same single request.
  const pending = S.approvals.pending;
  banner.hidden = !pending;
  if (pending && pending !== shownPending) {
    shownPending = pending;
    setChildren(banner, icon("hand", 16),
      h("span", { text: `Approval needed: ${pending.action} “${pending.target}”` }),
      h("button", { class: "btn btn-sm", text: "Review", onclick: () => dialog.open || dialog.showModal() }));
    setChildren(dialog, h("h2", { id: "approval-title", class: "sr-only", text: "Approve this action?" }), approvalCard(pending, ctl, "dialog"));
    if (!dialog.open) dialog.showModal();
  }
  if (!pending && shownPending) {
    shownPending = null;
    if (dialog.open) dialog.close();
  }
}

store.subscribe(render);
render(store.state);
ctl.init().then(() => render(store.state));
