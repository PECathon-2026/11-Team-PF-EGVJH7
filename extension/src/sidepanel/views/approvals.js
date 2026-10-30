import { h, icon, chip, card, empty, time, setChildren } from "../ui.js";

const RISK_TONE = { critical: "bad", high: "warn", medium: "info" };

export function approvalCard(pending, ctl, idPrefix = "inline") {
  return h("div", { class: "approval-card", id: `${idPrefix}-approval` },
    h("div", { class: "approval-head" }, icon("hand", 20), h("strong", { text: "Approval required" }), chip(pending.risk.label, RISK_TONE[pending.risk.level])),
    h("dl", { class: "kv-grid" },
      h("dt", { text: "Requested action" }), h("dd", { text: pending.action }),
      h("dt", { text: "Target element" }), h("dd", { text: pending.target || "(unlabelled element)" }),
      h("dt", { text: "Why you're asked" }), h("dd", { text: pending.why }),
      h("dt", { text: "Information used" }), h("dd", {}, pending.uses?.length
        ? h("ul", { class: "plain" }, ...pending.uses.map((u) => h("li", { class: "mono", text: `${u.type}: ${u.masked}` })))
        : h("span", { class: "muted", text: "No real personal data; synthetic values only" })),
      h("dt", { text: "Agent's reason" }), h("dd", { text: pending.agentReason || "(none given)" })),
    h("div", { class: "row gap" },
      h("button", { class: "btn grow", id: `${idPrefix}-deny`, onclick: () => ctl.resolveApproval(false) }, icon("x"), "Deny"),
      h("button", { class: "btn btn-danger grow", id: `${idPrefix}-approve`, onclick: () => ctl.resolveApproval(true) }, icon("check"), "Approve once")),
  );
}

export function approvalsView(store, ctl) {
  const pending = h("div");
  const history = h("ol", { class: "history", id: "approval-history" });

  const root = h("div", { class: "view" },
    card("Pending requests", pending),
    card("How approval is enforced",
      h("ul", { class: "plain checks small" },
        h("li", { text: "Deny executes nothing: the run stops before the page is touched." }),
        h("li", { text: "Approve once mints a single-use grant bound to one element, one action type and one page snapshot." }),
        h("li", { text: "Grants expire after 30 seconds and are wiped by any new snapshot." }),
        h("li", { text: "The page-side executor re-checks every payment, submission, risky link and card-number entry, and refuses without a valid grant, even if this panel is bypassed." }))),
    card("Approval history", history),
  );

  function update(S) {
    setChildren(pending, S.approvals.pending ? approvalCard(S.approvals.pending, ctl) : empty("Nothing waiting. The agent will stop here before any payment, submission or real card/Aadhaar/PAN entry."));
    setChildren(history, S.approvals.history.length
      ? S.approvals.history.map((a) => h("li", { class: "history-item" },
          h("span", { class: "mono small", text: time(a.decided) }),
          h("span", { text: `${a.action} “${a.target}”` }),
          chip(a.risk.level, RISK_TONE[a.risk.level]),
          chip(a.approved ? "Approved once" : "Denied", a.approved ? "warn" : "ok")))
      : [empty("No decisions yet.")]);
  }

  return { root, update };
}
