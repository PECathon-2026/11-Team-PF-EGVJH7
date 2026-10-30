// P2 detection: structural DOM hints + regex/checksum finders, merged and
// scored. Port of core/detect/{__init__,structural,merge}.py.

import { FINDERS } from "./patterns.js";

const AUTOCOMPLETE_MAP = {
  "cc-number": "CARD", "cc-csc": "CARD", "cc-exp": "CARD",
  "one-time-code": "OTP", "current-password": "PASSWORD",
  "new-password": "PASSWORD", email: "EMAIL", tel: "PHONE",
};

const KEYWORD_MAP = [
  [["card", "cvv", "cvc", "creditcard"], "CARD"],
  [["aadhaar", "aadhar", "uid"], "AADHAAR"],
  [["pan"], "PAN"],
  [["otp", "2fa", "verification"], "OTP"],
  [["password", "passwd", "pwd"], "PASSWORD"],
  [["api", "token", "secret", "key"], "API_KEY"],
];

const TYPE_PRIORITY = {
  CARD: 3, AADHAAR: 3, PAN: 3, PASSWORD: 3, OTP: 3, API_KEY: 3,
  EMAIL: 2, PHONE: 2, IP: 2, OTHER: 1, FACE: 1, PERSON: 1, ADDRESS: 1,
};

const RISK_WEIGHTS = {
  CARD: 10, AADHAAR: 10, PAN: 10, PASSWORD: 10, API_KEY: 10,
  EMAIL: 3, PHONE: 3, ADDRESS: 3, PERSON: 2, IP: 2,
};

export const SCANNED_FIELDS = ["text", "value", "label", "placeholder"];

// Controls that hold a choice or an action, not something the user typed:
// their label may say "Show password" or "Remember my email", but their
// value ("on", a button caption) is never the secret itself.
const NON_TEXT_INPUT_TYPES = new Set(["checkbox", "radio", "button", "submit", "reset", "image", "file", "range", "color"]);

export function isTextEntry(el) {
  const type = (el.type || "").trim().toLowerCase();
  return el.tag === "textarea" || (el.tag === "input" && !NON_TEXT_INPUT_TYPES.has(type));
}

function structuralHits(el) {
  // Page-structure hints only apply to fields a value is typed into. Text on
  // buttons, links and checkboxes is still covered by the pattern finders.
  if (!isTextEntry(el)) return [];
  const out = [];
  const value = el.value || "";
  const span = value ? [0, value.length] : null;
  const type = (el.type || "").trim().toLowerCase();
  const attrs = el.attrs || {};
  const hit = (t) => out.push({ type: t, source: "dom", elementId: el.id, field: "value", span, confidence: 1 });

  if (type === "password") hit("PASSWORD");

  const ac = (attrs.autocomplete || "").trim().toLowerCase();
  if (AUTOCOMPLETE_MAP[ac]) hit(AUTOCOMPLETE_MAP[ac]);

  const hay = [el.name, el.label, el.id, attrs.placeholder].filter(Boolean).join(" ").toLowerCase();
  const isEmailField = type === "email" || ac === "email" || hay.includes("email");

  for (const [words, t] of KEYWORD_MAP) {
    if (words.some((w) => hay.includes(w))) {
      hit(t);
      break;
    }
  }
  if (isEmailField) hit("EMAIL");
  if (!isEmailField && hay.includes("address")) hit("ADDRESS");

  const seen = new Set();
  return out.filter((d) => {
    const key = `${d.type}|${d.source}|${d.field}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function mergeDetections(dets) {
  const buckets = new Map();
  for (const d of dets) {
    const key = `${d.elementId}\u0000${d.field}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(d);
  }

  const merged = [];
  for (const group of buckets.values()) {
    const whole = group.filter((d) => d.span === null);
    const spans = group.filter((d) => d.span !== null);

    if (whole.length) {
      const best = whole.reduce((a, b) => ((TYPE_PRIORITY[b.type] || 0) > (TYPE_PRIORITY[a.type] || 0) ? b : a));
      best.confidence = Math.min(1, 0.5 + 0.25 * new Set(whole.map((d) => d.source)).size);
      merged.push(best);
      continue;
    }

    spans.sort((a, b) => a.span[0] - b.span[0] || b.span[1] - a.span[1]);
    const kept = [];
    for (const d of spans) {
      const k = kept.find((x) => d.span[0] < x.span[1] && x.span[0] < d.span[1]);
      if (k) {
        if ((TYPE_PRIORITY[d.type] || 0) > (TYPE_PRIORITY[k.type] || 0)) k.type = d.type;
        k.confidence = Math.min(1, k.confidence + 0.15);
      } else {
        kept.push({ ...d });
      }
    }
    merged.push(...kept);
  }
  return merged;
}

export function mosaicRisk(merged) {
  if (!merged.length) return 0;
  const base = merged.reduce((sum, d) => sum + Math.sqrt((RISK_WEIGHTS[d.type] || 1) * d.confidence), 0);
  const densityPenalty = 0.5 * Math.exp(merged.length / 5);
  return Math.round((base + densityPenalty) * 100) / 100;
}

/** Per-category contributions to mosaicRisk(), for explaining the score. */
export function riskBreakdown(merged) {
  const byType = new Map();
  for (const d of merged) {
    const row = byType.get(d.type) ?? { type: d.type, count: 0, contribution: 0, weight: RISK_WEIGHTS[d.type] || 1 };
    row.count += 1;
    row.contribution += Math.sqrt(row.weight * d.confidence);
    byType.set(d.type, row);
  }
  return {
    total: mosaicRisk(merged),
    densityPenalty: merged.length ? 0.5 * Math.exp(merged.length / 5) : 0,
    categories: [...byType.values()].sort((x, y) => y.contribution - x.contribution),
  };
}

export function detect(snapshot) {
  const raw = [];
  for (const el of snapshot.elements) {
    raw.push(...structuralHits(el));
    for (const field of SCANNED_FIELDS) {
      const content = el[field] || "";
      if (!content) continue;
      for (const [type, fn] of FINDERS) {
        for (const [start, end] of fn(content)) {
          raw.push({ type, source: "regex", elementId: el.id, field, span: [start, end], confidence: 1 });
        }
      }
    }
  }
  return mergeDetections(raw);
}
