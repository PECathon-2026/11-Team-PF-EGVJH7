import { h, icon, chip, card, time, setChildren } from "../ui.js";
import { SCENARIOS } from "../../core/scenarios.js";

const VERDICT = {
  pass: ["PASS", "ok"],
  partial: ["PARTIAL", "warn"],
  fail: ["FAIL", "bad"],
  error: ["ERROR", "bad"],
};
const STATUS = { pass: ["pass", "ok"], fail: ["fail", "bad"], unsupported: ["not supported", "warn"] };

export function testlabView(store, ctl) {
  const baseUrl = h("input", { id: "testlab-url", type: "text", spellcheck: false, "aria-label": "Test server URL" });
  baseUrl.addEventListener("change", () => ctl.updateSettings({ testlabBaseUrl: baseUrl.value.trim() || "http://127.0.0.1:8000" }));
  const runAll = h("button", { class: "btn btn-primary btn-block", id: "run-all", onclick: () => ctl.runAllScenarios() }, icon("flask"), "Run all five scenarios");
  const cards = new Map();

  const root = h("div", { class: "view" },
    card("PS-004 evaluation scenarios",
      h("p", { class: "muted small", text: "Each test opens a controlled page from testlab/pages (synthetic data only) in a background tab, runs the real pipeline on it, and compares the result with the expected behaviour. Scenarios always use the secure default settings." }),
      h("label", { class: "field" }, h("span", { class: "muted small", text: "Test server (start it with: python testlab/serve.py)" }), baseUrl),
      runAll),
    ...SCENARIOS.map((s, i) => {
      const body = h("div", { id: `scenario-${s.id}-result` });
      const button = h("button", { class: "btn btn-sm", id: `run-${s.id}`, onclick: () => ctl.runScenario(s.id) }, icon("play", 12), "Run test");
      const verdict = h("span");
      cards.set(s.id, { body, button, verdict });
      return h("section", { class: "card scenario", id: `scenario-${s.id}` },
        h("div", { class: "scenario-head" },
          h("span", { class: "scenario-num", text: String(i + 1) }),
          h("div", { class: "grow" }, h("h2", { class: "card-title", text: s.title }), h("div", { class: "muted small mono", text: s.page })),
          verdict, button),
        h("p", { class: "small", text: s.summary }),
        h("details", { class: "small" }, h("summary", { text: "Expected behaviour" }),
          h("ul", { class: "plain" },
            ...s.expected.map((e) => h("li", { text: `${e.type}: ${e.represent === "redacted" ? "redacted placeholder" : e.represent === "luhn-synthetic" ? "Luhn-valid synthetic card" : "synthetic value"}; real value never sent` })),
            ...(s.unsupported || []).map((u) => h("li", { class: "warn", text: `${u.name}: not supported. ${u.reason}` })))),
        body);
    }),
  );

  const rendered = new Map();
  function update(S) {
    if (document.activeElement !== baseUrl) baseUrl.value = S.settings.testlabBaseUrl;
    runAll.disabled = Boolean(S.testlab.running);
    for (const s of SCENARIOS) {
      const { body, button, verdict } = cards.get(s.id);
      const running = S.testlab.running === s.id;
      button.disabled = Boolean(S.testlab.running);
      const result = S.testlab.results[s.id];
      setChildren(verdict, running ? chip("Running…", "info") : result ? chip(...VERDICT[result.verdict]) : null);
      if (rendered.get(s.id) === result) continue;
      rendered.set(s.id, result);
      setChildren(body, !result ? null
        : result.verdict === "error"
          ? h("div", { class: "verdict bad" }, icon("alert"), h("span", { text: result.error }))
          : [
              h("details", { class: "checks-details", open: result.verdict !== "pass" },
                h("summary", { class: "small", text: `Ran ${time(result.at)} · ${result.checks.filter((c) => c.status === "pass").length}/${result.checks.length} checks passed · show evidence` }),
                h("ol", { class: "check-list" }, ...result.checks.map((c) => h("li", { class: `check ${c.status}` },
                  h("div", { class: "check-head" }, h("span", { class: "check-name", text: c.name }), chip(...STATUS[c.status])),
                  h("div", { class: "check-io small" },
                    h("span", { class: "muted", text: "Expected" }), h("span", { text: c.expected }),
                    h("span", { class: "muted", text: "Actual" }), h("span", { class: "mono", text: c.actual })),
                  c.evidence ? h("div", { class: "muted tiny", text: c.evidence }) : null)))),
            ]);
    }
  }

  return { root, update };
}
