import { h, icon, chip, card, empty, time, setChildren } from "../ui.js";
import { riskMeter } from "./risk.js";

export function overviewView(store, ctl) {
  const hero = h("section", { class: "hero" });
  const site = h("div", { class: "site-row" });
  const stats = h("div", { class: "stat-grid" });
  const agentInfo = h("div", { class: "kv-list" });
  const risk = h("div");
  const feed = h("ol", { class: "feed" });

  const root = h("div", { class: "view" },
    hero,
    card("Current site", site),
    card("This page", stats,
      h("button", { class: "btn btn-primary btn-block", id: "overview-scan", onclick: () => ctl.scanCurrentPage() },
        icon("scan"), "Scan current page")),
    card("AI agent", agentInfo),
    risk,
    card("Latest security activity", feed),
  );

  function update(S) {
    const on = S.settings.firewallEnabled;
    const toggle = h("input", {
      type: "checkbox", role: "switch", id: "firewall-toggle", checked: on,
      "aria-label": "Firewall protection",
      onchange: (e) => ctl.updateSettings({ firewallEnabled: e.target.checked }),
    });
    setChildren(hero,
      h("div", { class: `hero-shield ${on ? "on" : "off"}` }, icon(on ? "shieldCheck" : "shieldOff", 30)),
      h("div", { class: "hero-text" },
        h("div", { class: `hero-status ${on ? "ok" : "bad"}`, id: "firewall-status", text: on ? "FIREWALL ACTIVE" : "FIREWALL INACTIVE" }),
        h("div", { class: "muted small", text: on
          ? (S.selfTest ? (S.selfTest.ok ? `Self-test passed · ${time(S.selfTest.ranAt)}` : "Self-test FAILED: nothing will be sent") : "Running self-test…")
          : "Protection is off: PrivacyLens sends nothing to the AI." })),
      h("label", { class: "switch big" }, toggle, h("span", { class: "switch-track", "aria-hidden": "true" })),
    );

    const mon = S.tab.monitoring;
    setChildren(site,
      h("div", { class: "site-main" },
        icon("globe"),
        h("span", { class: "mono", text: S.tab.origin || "Not a web page" })),
      S.tab.web
        ? (S.tab.access ? chip("Access granted", "ok") : h("button", { class: "btn btn-sm", onclick: () => ctl.requestAccess(), text: "Allow on this site" }))
        : chip("Unsupported page", "neutral"),
      h("div", { class: "site-meta" },
        h("span", { class: `dot ${mon ? "dot-live" : ""}` }),
        h("span", { class: "small muted", text: mon ? `Monitoring active · overlay ${mon.overlayVisible ? "on" : "off"}` : "Not monitoring (scan or run to attach)" }),
        S.settings.blockedSites.includes(S.tab.host) ? chip("Never-send list", "bad") : null),
    );

    const scan = S.scan;
    const pending = S.approvals.pending ? 1 : 0;
    const tile = (label, value, tone = "", id = "") => h("div", { class: `stat ${tone}`, id: id || null },
      h("div", { class: "stat-value", text: value }), h("div", { class: "stat-label", text: label }));
    setChildren(stats,
      tile("Sensitive values detected", scan ? scan.rows.length : "—", "", "stat-detected"),
      tile("Values protected", scan ? scan.rows.filter((r) => r.action !== "none").length : "—", scan ? "ok" : "", "stat-protected"),
      tile("Injections quarantined", scan ? scan.injections.filter((i) => i.quarantined || i.hidden).length : "—", scan?.injections.length ? "warn" : ""),
      tile("Blocked requests", S.stats.blocked, S.stats.blocked ? "bad" : ""),
      tile("Approvals pending", pending, pending ? "warn" : "", "stat-pending"),
      tile("Last scan", scan ? time(scan.at) : "never"),
    );

    const mode = S.settings.mode === "gemini" && !S.settings.localOnly;
    setChildren(agentInfo,
      kv("Privacy mode", mode ? "Cloud AI · sanitized data only" : "Local-only · no network"),
      kv("Agent", mode ? `Gemini (${S.settings.model})` : "Offline mock agent"),
      kv("Connection", !mode ? chip("Not needed", "neutral")
        : !S.apiKeySet ? chip("Not configured", "warn")
        : S.gemini?.ok ? chip("Connected", "ok")
        : S.gemini?.ok === false ? chip(S.gemini.message, "bad")
        : chip("Key set · untested", "info")),
      kv("Run status", S.agent.running ? chip("Running", "info") : h("span", { class: `small ${S.agent.status.tone}`, text: S.agent.status.text })),
    );

    setChildren(risk, riskMeter(S));

    setChildren(feed, S.activity.length
      ? S.activity.slice(0, 8).map((a) => h("li", { class: `feed-item ${a.tone}` },
          h("span", { class: "feed-time mono", text: time(a.at) }), h("span", { text: a.text })))
      : [empty("No activity yet. Scan a page or run a task.")]);
  }

  return { root, update };
}

export const kv = (k, v) => h("div", { class: "kv" }, h("span", { class: "muted small", text: k }), typeof v === "string" ? h("span", { text: v }) : v);
