import { h, icon, chip, card, empty, time, setChildren, TONE_BY_SEVERITY } from "../ui.js";
import { labelOf, severityOf } from "../../core/taxonomy.js";
import { luhnOk, verhoeffOk } from "../../core/patterns.js";
import { INJECTION_REASONS } from "../../core/sanitize.js";

const ACTION_TEXT = {
  replaced: "Replaced with a format-preserving synthetic value. The real value is kept only in this panel's memory and restored on the page if you approve.",
  redacted: "Replaced with a typed placeholder. This value can never be typed back by the agent.",
};

// Checks run on the AI-side (synthetic) text only, so they are safe to show.
function formatChecks(field) {
  const out = [];
  if (!field.actions.includes("replaced")) return out;
  const groups = field.after.match(/\d[\d -]{10,22}\d/g) || [];
  if (field.types.includes("CARD")) {
    for (const g of groups) {
      const digits = g.replace(/\D/g, "");
      if (digits.length >= 13) out.push(`Synthetic card ${luhnOk(digits) ? "passes" : "fails"} Luhn ${luhnOk(digits) ? "✓" : "✗"}`);
    }
  }
  if (field.types.includes("AADHAAR")) {
    for (const g of groups) {
      const digits = g.replace(/\D/g, "");
      if (digits.length === 12) out.push(`Synthetic Aadhaar ${verhoeffOk(digits) ? "passes" : "fails"} Verhoeff ${verhoeffOk(digits) ? "✓" : "✗"}`);
    }
  }
  if (field.types.includes("EMAIL") && /@example\.com/.test(field.after)) out.push("Synthetic email uses the reserved example.com domain ✓");
  return out;
}

const clip = (text, n = 220) => (text.length > n ? `${text.slice(0, n - 1)}…` : text);

export function scannerView(store, ctl) {
  const header = h("div", { class: "scan-head" });
  const list = h("div", { class: "compare-list", id: "compare-list" });
  const payload = h("pre", { class: "payload mono", id: "ai-payload" });

  const root = h("div", { class: "view" },
    card(null, header),
    h("div", { class: "compare-legend" },
      h("span", { class: "legend-col", text: "WHAT YOU SEE" }), h("span", { class: "legend-col ai", text: "WHAT AI SEES" })),
    list,
    card("Exact AI payload",
      h("p", { class: "muted small", text: "This is the complete request the agent would receive for this page: synthetic values and placeholders only. It passed the egress firewall before being shown here." }),
      h("details", {}, h("summary", { class: "small", text: "Show JSON" }), payload)),
  );

  let rendered;
  function update(S) {
    const scan = S.scan;
    const allSafe = scan && scan.egress.ok && scan.honeytokenOk;
    setChildren(header,
      h("div", { class: "scan-title" },
        h("div", {}, h("div", { class: "card-title", text: "Privacy Scanner" }),
          h("div", { class: "muted small", text: scan ? `Last scan ${time(scan.at)} · ${scan.source}` : "No scan yet for this session." })),
        h("button", { class: "btn btn-primary", id: "scan-button", onclick: () => ctl.scanCurrentPage() }, icon("scan"), "Scan Current Page")),
      scan ? h("div", { class: `protect-banner ${allSafe ? "ok" : "bad"}`, id: "protect-banner" },
        icon(allSafe ? "shieldCheck" : "alert"),
        h("span", { text: allSafe
          ? `Protected: ${scan.rows.length} value(s) transformed, ${scan.protectedValues} distinct secret(s) kept local. Outgoing request passed the firewall.`
          : `Blocked: ${scan.egress.reasons[0] || "honeytoken check failed"}. Nothing would be sent.` })) : null,
      scan?.hiddenDropped ? h("div", { class: "muted small", text: `${scan.hiddenDropped} invisible element(s) withheld from the AI entirely.` }) : null,
    );

    if (scan === rendered) return; // keep open "Inspect" panels intact
    rendered = scan;
    if (!scan) {
      setChildren(list, empty("Press “Scan Current Page” to compare what you see with what the AI would receive."));
      payload.textContent = "";
      return;
    }

    const rows = scan.fields.map((field) => {
      const checks = formatChecks(field);
      return h("article", { class: "compare", dataset: { types: field.types.join(" ") } },
        h("div", { class: "compare-meta" },
          ...field.categories.map((c) => chip(labelOf(c), TONE_BY_SEVERITY[severityOf(c)])),
          ...field.actions.map((a) => chip(a === "replaced" ? "Replaced" : "Redacted", a === "replaced" ? "info" : "neutral")),
          h("span", { class: "muted small truncate", text: field.label })),
        h("div", { class: "compare-cols" },
          h("div", { class: "col-you mono", text: clip(field.youSee) }),
          h("div", { class: "col-arrow" }, icon("lock", 14)),
          h("div", { class: "col-ai mono", text: clip(field.after) })),
        h("details", { class: "inspect" },
          h("summary", { class: "small", text: "Inspect transformation" }),
          h("dl", { class: "kv-grid small" },
            h("dt", { text: "Location" }), h("dd", { text: `${field.label} · ${field.field}${field.hidden ? " (invisible)" : ""}` }),
            h("dt", { text: "Detected by" }), h("dd", { text: field.methods.join("; ") }),
            h("dt", { text: "Method" }), h("dd", { text: field.actions.map((a) => ACTION_TEXT[a]).join(" ") }),
            ...checks.flatMap((c, i) => [h("dt", { text: i ? "" : "Format check" }), h("dd", { text: c })]),
            h("dt", { text: "Real value" }), h("dd", { text: "Never displayed. Masked above; it exists only in panel memory and on the page itself." }))));
    });

    const injections = scan.injections.map((inj) => h("article", { class: "compare quarantine" },
      h("div", { class: "compare-meta" },
        chip("Prompt injection", "bad"),
        chip(inj.quarantined || inj.hidden ? "Quarantined" : "Allowed (protection off)", inj.quarantined || inj.hidden ? "bad" : "warn"),
        h("span", { class: "muted small", text: inj.hidden ? "invisible element" : "visible text" })),
      h("div", { class: "compare-cols" },
        h("div", { class: "col-you small", text: inj.preview }),
        h("div", { class: "col-arrow" }, icon("lock", 14)),
        h("div", { class: "col-ai mono small", text: inj.reachedAI ? "SENT TO AI" : inj.hidden ? "(withheld)" : "[QUARANTINED]" })),
      h("div", { class: "muted small", text: inj.categories.map((c) => INJECTION_REASONS[c]).join(" ") })));

    setChildren(list, rows.length || injections.length ? [...rows, ...injections] : [empty("No sensitive values or injections found on this page.")]);
    payload.textContent = JSON.stringify(scan.aiView, null, 2);
  }

  return { root, update };
}
