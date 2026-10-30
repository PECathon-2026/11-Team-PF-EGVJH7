import { h, icon, chip, card, empty, time, setChildren } from "../ui.js";

export function validationView(store, ctl) {
  const result = h("div", { id: "selftest-results" });
  const mechanisms = h("div", { class: "mech-list" });

  const root = h("div", { class: "view" },
    card("Firewall self-test",
      h("p", { class: "muted small", text: "Plants fresh secrets and decoys, pushes them through the real detection, sanitization and egress code, and checks that every leak is blocked. Runs automatically when the panel opens and before every agent run." }),
      h("button", { class: "btn btn-primary btn-block", id: "run-selftest", onclick: () => ctl.runSelfTest() }, icon("shieldCheck"), "Run firewall self-test"),
      result),
    card("Protection mechanisms", mechanisms),
  );

  let renderedTest;
  function update(S) {
    if (S.selfTest !== renderedTest) {
      renderedTest = S.selfTest;
      const t = S.selfTest;
      setChildren(result, t
        ? [
            h("div", { class: `verdict ${t.ok ? "ok" : "bad"}`, id: "selftest-verdict" },
              icon(t.ok ? "shieldCheck" : "alert"),
              h("span", { text: t.ok ? `All ${t.evidence.length} checks passed` : `${t.evidence.filter((e) => !e.passed).length} check(s) FAILED: agent runs are blocked` }),
              h("span", { class: "muted small", text: time(t.ranAt) })),
            h("ol", { class: "evidence" }, ...t.evidence.map((e) => h("li", { class: e.passed ? "ok" : "bad" },
              h("span", { class: "ev-icon" }, icon(e.passed ? "check" : "x", 14)),
              h("div", {}, h("div", { text: e.name }), h("div", { class: "muted small mono", text: e.detail }))))),
          ]
        : [empty("Not run yet.")]);
    }

    const s = S.settings;
    const net = ctl.networkPolicy();
    const last = S.scan;
    const row = (name, state, tone, detail) => h("div", { class: "mech" },
      h("div", { class: "mech-head" }, h("span", { text: name }), chip(state, tone)),
      h("div", { class: "muted small", text: detail }));
    setChildren(mechanisms,
      row("Outgoing request inspection", "Always on", "ok", `${S.stats.inspected} request(s) inspected this session, ${S.stats.blocked} blocked. Every request is checked before the agent is called and, in Gemini mode, again as the exact HTTP body.`),
      row("Second-opinion scanning", "Always on", "ok", "Outgoing text is re-scanned with the detectors; any card, Aadhaar, PAN or API key that is not one of our own synthetic values blocks the request."),
      row("Sensitive-data leakage prevention", s.detectionEnabled ? "On" : "Off: sending disabled", s.detectionEnabled ? "ok" : "bad", last ? `Last scan: ${last.protectedValues} distinct secret(s) kept local.` : "No scan yet."),
      row("Decoy / canary detection", "Always on", "ok", `A fresh honeytoken card is planted in every snapshot: ${S.stats.honeytokenPassed}/${S.stats.honeytokenChecks} removed correctly this session.`),
      row("Invisible-text filtering", s.invisibleFilter ? "On" : "Off", s.invisibleFilter ? "ok" : "warn", last ? `${last.hiddenDropped} invisible element(s) withheld on the last scan.` : "No scan yet."),
      row("Prompt-injection quarantine", s.injectionProtection ? "On" : "Off", s.injectionProtection ? "ok" : "warn", last ? `${last.injections.length} instruction-like element(s) on the last scan.` : "No scan yet."),
      row("Network restriction", "Enforced by Chrome", "ok", `Extension CSP connect-src: ${net.connect}. The panel cannot send data anywhere else, even by mistake.`),
      row("Fail-closed behaviour", S.selfTest?.checks?.failsClosedOnEmptyInventory ? "Verified" : "Not verified", S.selfTest?.checks?.failsClosedOnEmptyInventory ? "ok" : "warn",
        "Empty inventory, uninspectable payloads, a surviving honeytoken, a failed self-test or protection switched off all stop transmission."),
    );
  }

  return { root, update };
}
