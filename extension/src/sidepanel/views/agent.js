import { h, icon, chip, card, empty, setChildren } from "../ui.js";
import { STAGES } from "../../core/orchestrator.js";

const STAGE_LABEL = { observe: "Observe", sanitize: "Sanitize", reason: "Reason", validate: "Validate", approve: "Approve", execute: "Execute" };
const STAGE_HINT = {
  observe: "Snapshot of the live page",
  sanitize: "Detect, replace, firewall check",
  reason: "AI proposes one action",
  validate: "Strict parsing + policy",
  approve: "You decide on risky actions",
  execute: "Page-side executor re-checks",
};
const EXAMPLES = [
  "Sign in to my account",
  "Create an account",
  "Fill in the registration form",
  "Go to the cart and pay",
  "Complete the checkout and pay",
];
const DECISION = {
  allowed: ["Allowed by policy", "ok"],
  needs_approval: ["Needs approval", "warn"],
  denied: ["Denied by policy", "bad"],
  done: ["Task complete", "ok"],
};

export function agentView(store, ctl) {
  const modeBanner = h("div");
  const task = h("textarea", { id: "task", rows: 3, placeholder: "Describe a task in plain language…", "aria-label": "Task" });
  const steps = h("input", { id: "max-steps", type: "number", min: 1, max: 20, value: "12", "aria-label": "Maximum steps" });
  const run = h("button", { class: "btn btn-primary grow", id: "run", onclick: () => ctl.runTask(task.value) }, icon("play"), "Run privately");
  const stop = h("button", { class: "btn", id: "stop", onclick: () => ctl.stop() }, icon("stop"), "Stop");
  const status = h("div", { class: "status", id: "status", role: "status", "aria-live": "polite" });
  const stepper = h("ol", { class: "stepper", id: "stepper" });
  const context = h("div");
  const actions = h("ol", { class: "actions", id: "actions" });

  steps.addEventListener("change", () => ctl.updateSettings({ maxSteps: Number(steps.value) }));

  const root = h("div", { class: "view" },
    modeBanner,
    card("Task",
      task,
      h("div", { class: "examples" }, ...EXAMPLES.map((text) => h("button", { class: "example", text, onclick: () => { task.value = text; task.focus(); } }))),
      h("div", { class: "row gap" }, run, stop,
        h("label", { class: "steps-field" }, h("span", { class: "muted small", text: "Max steps" }), steps)),
      status),
    card("Execution lifecycle", stepper),
    card("What the AI was given", context),
    card("Proposed actions", actions),
  );

  let ctxRendered;
  function update(S) {
    const gemini = S.settings.mode === "gemini";
    setChildren(modeBanner, gemini
      ? h("div", { class: `mode-banner ${S.settings.localOnly || !S.apiKeySet ? "warn" : "cloud"}`, id: "mode-banner" },
          icon("globe"),
          h("div", {},
            h("strong", { text: `Gemini · ${S.settings.model}` }),
            h("div", { class: "small", text: S.settings.localOnly
              ? "Local-only mode is on, so cloud AI is disabled. Turn it off in Settings to use Gemini."
              : !S.apiKeySet ? "Not configured: add an API key in Settings → AI configuration."
              : S.gemini?.ok ? "Connected. Only sanitized, synthetic data is sent."
              : "Key set (connection not yet tested). Only sanitized, synthetic data is sent." })),
          !S.apiKeySet || S.settings.localOnly ? h("button", { class: "btn btn-sm", text: "Settings", onclick: () => store.set({ view: "settings" }) }) : null)
      : h("div", { class: "mode-banner local", id: "mode-banner" },
          icon("lock"),
          h("div", {},
            h("strong", { text: "Offline mock agent" }),
            h("div", { class: "small", text: "A local rule-based planner: fills empty form fields from Settings → My details (or the synthetic test identity), then clicks the button matching your task, following links across pages. No network and no real AI reasoning." }))));

    if (document.activeElement !== steps) steps.value = String(S.settings.maxSteps);
    run.disabled = S.agent.running;
    stop.disabled = !S.agent.running;
    status.textContent = S.agent.status.text;
    status.className = `status ${S.agent.status.tone}`;

    setChildren(stepper, STAGES.map((name) => {
      const st = S.agent.stages[name];
      const glyph = { done: "check", blocked: "x", active: "gauge", skipped: "check" }[st.state];
      return h("li", { class: `stage ${st.state}`, dataset: { stage: name } },
        h("span", { class: "stage-dot" }, glyph ? icon(glyph, 12) : null),
        h("div", {},
          h("div", { class: "stage-name", text: STAGE_LABEL[name] }),
          h("div", { class: "muted small", text: st.detail || (st.state === "skipped" ? "Not required" : STAGE_HINT[name]) })));
    }));

    const scan = S.scan;
    if (scan !== ctxRendered) setChildren(context, scan && scan.source.startsWith("agent")
      ? [
          h("div", { class: "kv-list" },
            h("div", { class: "kv" }, h("span", { class: "muted small", text: "Page" }), h("span", { class: "mono small", text: scan.aiView.url })),
            h("div", { class: "kv" }, h("span", { class: "muted small", text: "Task as sent" }), h("span", { class: "mono small", text: scan.aiView.task })),
            h("div", { class: "kv" }, h("span", { class: "muted small", text: "Elements" }), h("span", { text: `${scan.aiView.elements.length} (${scan.rows.length} protected value(s), ${scan.hiddenDropped} invisible withheld)` }))),
          h("details", {}, h("summary", { class: "small", text: "Show sanitized context" }), h("pre", { class: "payload mono", text: JSON.stringify(scan.aiView, null, 2) })),
        ]
      : [h("div", { class: "empty", text: "Run a task to see the exact sanitized context the agent received." })]);
    ctxRendered = scan;

    setChildren(actions, S.agent.actions.length
      ? S.agent.actions.map((a) => {
          const [label, tone] = DECISION[a.decision] || [a.decision, "neutral"];
          return h("li", { class: "action" },
            h("div", { class: "action-head" },
              h("span", { class: "mono small", text: `#${a.step + 1}` }),
              h("strong", { text: `${a.type}${a.element_id ? ` → ${a.element_id}` : ""}` }),
              chip(label, tone),
              a.exec ? chip(a.exec === "executed" ? "Executed" : "Refused", a.exec === "executed" ? "ok" : "bad") : null),
            a.reason ? h("div", { class: "muted small", text: `AI reasoning: ${a.reason}` }) : null);
        })
      : [empty("No actions proposed yet.")]);
  }

  return { root, update };
}
