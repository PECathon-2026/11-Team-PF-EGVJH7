import { h, icon, chip, card, empty, time, setChildren, toggle } from "../ui.js";

export function settingsView(store, ctl) {
  const protection = h("div");
  const ai = h("div");
  const sites = h("div");
  const data = h("div");
  const appearance = h("div");

  const apiKey = h("input", { id: "api-key", type: "password", autocomplete: "off", spellcheck: false, placeholder: "Paste a Gemini API key", "aria-label": "Gemini API key" });
  const model = h("input", { id: "model", type: "text", spellcheck: false, "aria-label": "Model" });
  apiKey.addEventListener("change", () => ctl.setApiKey(apiKey.value.trim()));
  model.addEventListener("change", () => ctl.updateSettings({ model: model.value.trim() || "gemini-2.5-flash" }));

  const root = h("div", { class: "view" },
    card("Protection", protection),
    card("AI configuration", ai),
    card("Website permissions", sites),
    card("Data handling", data),
    card("Appearance", appearance),
  );

  let origins = [];
  let originsLoaded = false;
  async function loadOrigins() {
    origins = await ctl.grantedOrigins();
    originsLoaded = true;
    update(store.state);
  }

  let lastKey;
  function update(S) {
    const s = S.settings;
    // Rebuild only when something shown here changed (keeps open selects open).
    const key = JSON.stringify([s, S.tab.origin, S.tab.access, S.tab.web, S.apiKeySet, S.gemini, originsLoaded, origins]);
    if (key === lastKey) return;
    lastKey = key;
    const set = (patch) => ctl.updateSettings(patch);

    setChildren(protection,
      toggle({ id: "set-firewall", checked: s.firewallEnabled, label: "Firewall", hint: "Off = nothing is sent to the AI at all (it never sends raw data).", onChange: (v) => set({ firewallEnabled: v }) }),
      toggle({ id: "set-detection", checked: s.detectionEnabled, label: "Sensitive-data detection", hint: "Off = pages cannot be sanitized, so sending is disabled.", onChange: (v) => set({ detectionEnabled: v }) }),
      toggle({ id: "set-injection", checked: s.injectionProtection, label: "Prompt-injection protection", hint: "Quarantines instruction-like page text.", onChange: (v) => set({ injectionProtection: v }) }),
      toggle({ id: "set-invisible", checked: s.invisibleFilter, label: "Invisible-text filtering", hint: "Withholds hidden elements from the AI.", onChange: (v) => set({ invisibleFilter: v }) }),
      toggle({ id: "set-overlay", checked: s.overlay, label: "AI-Eye overlay", hint: "Highlights protected fields on the page.", onChange: (v) => set({ overlay: v }) }),
      !s.injectionProtection || !s.invisibleFilter
        ? h("div", { class: "warning small" }, icon("alert", 14), h("span", { text: "Reduced protection: page content may carry instructions to the AI. Secrets are still replaced." }))
        : null);

    if (document.activeElement !== model) model.value = s.model;
    setChildren(ai,
      h("label", { class: "field" }, h("span", { class: "muted small", text: "Agent" }),
        h("select", { id: "mode", onchange: (e) => set({ mode: e.target.value }) },
          h("option", { value: "mock", text: "Offline mock agent (no network)", selected: s.mode === "mock" }),
          h("option", { value: "gemini", text: "Gemini (cloud, sanitized data only)", selected: s.mode === "gemini" }))),
      toggle({ id: "set-local", checked: s.localOnly, label: "Local-only mode", hint: "Blocks every cloud AI call, whatever the agent setting.", onChange: (v) => set({ localOnly: v }) }),
      h("label", { class: "field" }, h("span", { class: "muted small", text: "Gemini API key: kept in memory only (chrome.storage.session), cleared when the browser closes" }), apiKey),
      h("div", { class: "row gap" }, chip(S.apiKeySet ? "Key set" : "No key", S.apiKeySet ? "ok" : "neutral"),
        S.apiKeySet ? h("button", { class: "btn btn-sm", text: "Forget key", onclick: () => { apiKey.value = ""; ctl.setApiKey(""); } }) : null),
      h("label", { class: "field" }, h("span", { class: "muted small", text: "Model" }), model),
      h("div", { class: "row gap" },
        h("button", { class: "btn btn-sm", id: "test-connection", disabled: !S.apiKeySet, onclick: () => ctl.testConnection() }, icon("link", 12), "Test connection"),
        S.gemini ? chip(S.gemini.message, S.gemini.ok ? "ok" : S.gemini.ok === false ? "bad" : "info") : null),
      h("p", { class: "muted tiny", text: "The connection test reads the model's metadata only; it sends no page data." }));

    const blocked = s.blockedSites.includes(S.tab.host);
    setChildren(sites,
      h("div", { class: "kv" }, h("span", { class: "muted small", text: "Current site" }), h("span", { class: "mono small", text: S.tab.origin || "—" })),
      h("div", { class: "row gap wrap" },
        S.tab.web ? (S.tab.access ? chip("Access granted", "ok") : h("button", { class: "btn btn-sm", text: "Allow on this site", onclick: () => ctl.requestAccess() })) : chip("Not a web page", "neutral"),
        S.tab.web ? toggle({ id: "set-block-site", checked: blocked, label: "Never send this site to the AI", onChange: (v) => ctl.setSiteBlocked(S.tab.host, v) }) : null),
      h("h3", { class: "sub", text: "Sites with access" }),
      !originsLoaded ? h("button", { class: "btn btn-sm", text: "Load list", onclick: loadOrigins })
        : origins.length ? h("ul", { class: "plain site-list" }, ...origins.map((o) => h("li", {},
            h("span", { class: "mono small", text: o }),
            h("button", { class: "btn btn-sm", text: "Revoke", onclick: async () => { await ctl.revokeOrigin(o); loadOrigins(); } }))))
        : empty("No sites granted."),
      h("h3", { class: "sub", text: "Never-send list" }),
      s.blockedSites.length ? h("ul", { class: "plain site-list" }, ...s.blockedSites.map((host) => h("li", {},
        h("span", { class: "mono small", text: host }),
        h("button", { class: "btn btn-sm", text: "Remove", onclick: () => ctl.setSiteBlocked(host, false) }))))
        : empty("Empty."));

    const strict = ["CARD", "AADHAAR", "PAN"].every((t) => s.redactTypes.includes(t));
    setChildren(data,
      toggle({ id: "set-strict", checked: strict, label: "Strict redaction for cards, Aadhaar and PAN",
        hint: "Placeholders instead of format-preserving synthetic values. Safer, but the agent can no longer fill these fields for you.",
        onChange: (v) => set({ redactTypes: v ? ["CARD", "AADHAAR", "PAN"] : [] }) }),
      h("div", { class: "kv" }, h("span", { class: "muted small", text: "Log retention" }), h("span", { text: "This session only (memory). Persistent logs are not supported, by design." })),
      h("button", { class: "btn btn-sm", text: "Clear ledger now", onclick: () => ctl.clearLedger() }),
      h("h3", { class: "sub", text: "What leaves your browser" }),
      h("ul", { class: "plain small checks" },
        h("li", { text: "Offline agent / local-only: nothing. All detection, sanitization and validation runs inside the extension." }),
        h("li", { text: "Gemini: one request per step to generativelanguage.googleapis.com with the sanitized page (synthetic values, placeholders, no URL query strings), your sanitized task and the action history. No screenshots, no cookies." }),
        h("li", { text: "Never sent: real values, the synthetic-to-real mapping, the ledger, your API key (except as the auth header to Google)." })));

    setChildren(appearance,
      h("label", { class: "field" }, h("span", { class: "muted small", text: "Theme" }),
        h("select", { id: "theme", onchange: (e) => set({ theme: e.target.value }) },
          ...["dark", "light", "system"].map((t) => h("option", { value: t, text: t[0].toUpperCase() + t.slice(1), selected: s.theme === t })))));
  }

  return { root, update };
}
