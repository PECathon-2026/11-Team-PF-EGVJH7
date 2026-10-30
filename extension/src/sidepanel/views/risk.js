// Mosaic-risk meter. Numbers come straight from riskBreakdown() /
// mosaicRisk(), the JS port of core/detect/merge.py:calculate_mosaic_risk
// (parity-tested against Python).

import { h, card, empty, time } from "../ui.js";
import { labelOf } from "../../core/taxonomy.js";

export function riskLevel(score) {
  if (score === 0) return { label: "None", tone: "ok" };
  if (score < 5) return { label: "Low", tone: "ok" };
  if (score < 15) return { label: "Moderate", tone: "warn" };
  return { label: "High", tone: "bad" };
}

export function riskMeter(S) {
  const scan = S.scan;
  if (!scan) return card("Mosaic privacy risk", empty("Scan a page to compute its risk score."));

  const { total, categories, densityPenalty } = scan.risk;
  const level = riskLevel(total);
  const max = Math.max(...categories.map((c) => c.contribution), densityPenalty, 1);
  const last = S.riskHistory.at(-1);

  return card("Mosaic privacy risk",
    h("div", { class: "risk-head" },
      h("div", {},
        h("span", { class: `risk-score ${level.tone}`, id: "risk-score", text: total.toFixed(2) }),
        h("span", { class: `chip chip-${level.tone}`, text: level.label })),
      h("div", { class: "muted small", text: `${categories.reduce((n, c) => n + c.count, 0)} identity factor(s) on this page` })),
    h("div", { class: "risk-bar" }, h("div", { class: `risk-fill ${level.tone}`, style: `width:${Math.min(100, (total / 40) * 100)}%` })),
    h("p", { class: "muted small", text: "Each factor adds √(weight × confidence); several factors together add a density penalty, because combined they can re-identify you." }),
    h("div", { class: "contrib" },
      ...categories.map((c) => h("div", { class: "contrib-row" },
        h("span", { class: "contrib-label", text: `${labelOf(c.type === "API_KEY" ? "API_KEY" : c.type)} ×${c.count}` }),
        h("span", { class: "contrib-bar" }, h("span", { style: `width:${(c.contribution / max) * 100}%` })),
        h("span", { class: "mono small", text: `+${c.contribution.toFixed(2)}` }))),
      categories.length ? h("div", { class: "contrib-row" },
        h("span", { class: "contrib-label", text: "Density penalty" }),
        h("span", { class: "contrib-bar penalty" }, h("span", { style: `width:${(densityPenalty / max) * 100}%` })),
        h("span", { class: "mono small", text: `+${densityPenalty.toFixed(2)}` })) : null),
    last ? h("div", { class: "risk-change" },
      h("span", { class: "small", text: last.delta == null ? "Baseline" : `${last.delta >= 0 ? "▲" : "▼"} ${Math.abs(last.delta).toFixed(2)} since previous scan` }),
      h("span", { class: "muted small", text: last.why })) : null,
    S.riskHistory.length > 1 ? h("ol", { class: "risk-history" },
      ...S.riskHistory.slice(-6).reverse().map((r) => h("li", {},
        h("span", { class: "mono small", text: time(r.at) }),
        h("span", { class: "small", text: r.host }),
        h("span", { class: `mono small ${riskLevel(r.total).tone}`, text: r.total.toFixed(2) })))) : null,
  );
}
