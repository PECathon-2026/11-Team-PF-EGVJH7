import { h, chip, card, empty, setChildren, TONE_BY_SEVERITY } from "../ui.js";
import { CATEGORIES, labelOf, severityOf, SEVERITY_RANK } from "../../core/taxonomy.js";
import { INJECTION_REASONS } from "../../core/sanitize.js";

export function threatsView(store) {
  const grid = h("div", { class: "cat-grid", id: "category-grid" });
  const table = h("div");
  const injections = h("div", { id: "injection-list" });

  const root = h("div", { class: "view" },
    card("Detection categories", grid),
    card("Detected on this page", table),
    card("Prompt-injection defence",
      h("p", { class: "muted small", text: "Page content is untrusted data. Instruction-like text is quarantined before the AI sees it, invisible text is withheld entirely, and the agent's system prompt tells it never to follow page instructions." }),
      injections),
  );

  let rendered;
  function update(S) {
    if (S.scan === rendered) return;
    rendered = S.scan;
    const rows = S.scan?.rows || [];
    const counts = {};
    for (const r of rows) counts[r.category] = (counts[r.category] || 0) + 1;

    setChildren(grid, CATEGORIES.map((c) => h("div", { class: `cat ${counts[c.id] ? "hit" : ""}`, dataset: { category: c.id }, title: c.note || "" },
      h("div", { class: "cat-count", text: S.scan ? String(counts[c.id] || 0) : "—" }),
      h("div", { class: "cat-label", text: c.label }),
      chip(c.severity, TONE_BY_SEVERITY[c.severity]),
      c.note ? h("div", { class: "muted tiny", text: c.note }) : null)));

    const sorted = [...rows].sort((a, b) => SEVERITY_RANK[severityOf(b.category)] - SEVERITY_RANK[severityOf(a.category)]);
    setChildren(table, sorted.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
          h("thead", {}, h("tr", {}, ...["Threat", "Severity", "Method", "Location", "Result"].map((t) => h("th", { text: t })))),
          h("tbody", {}, ...sorted.map((r) => h("tr", {},
            h("td", { text: labelOf(r.category) }),
            h("td", {}, chip(severityOf(r.category), TONE_BY_SEVERITY[severityOf(r.category)])),
            h("td", { class: "small", text: r.method }),
            h("td", { class: "small", text: `${r.label} · ${r.field}${r.hidden ? " (invisible)" : ""}` }),
            h("td", {}, chip(r.action === "replaced" ? "Synthetic" : "Redacted", "ok")))))))
      : empty(S.scan ? "No sensitive data detected on this page." : "Scan a page to populate this view."));

    const injs = S.scan?.injections || [];
    setChildren(injections, injs.length
      ? injs.map((i) => h("article", { class: "injection" },
          h("div", { class: "row gap wrap" },
            chip(i.hidden ? "Hidden text" : "Visible text", i.hidden ? "warn" : "info"),
            chip(i.quarantined || i.hidden ? "Quarantined" : "NOT quarantined", i.quarantined || i.hidden ? "ok" : "bad"),
            chip(i.reachedAI ? "Reached the AI" : "Never reached the AI", i.reachedAI ? "bad" : "ok")),
          h("blockquote", { class: "quote", text: i.preview }),
          h("ul", { class: "plain small" }, ...i.categories.map((c) => h("li", { text: `${c.replace(/_/g, " ")}: ${INJECTION_REASONS[c]}` })))))
      : [empty(S.scan ? "No instruction-like content found on this page." : "Scan a page to check for prompt injections.")]);
  }

  return { root, update };
}
