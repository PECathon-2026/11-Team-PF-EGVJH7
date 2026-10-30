// P3 sanitizer: turns a raw page snapshot into the minimal "AI view".
//
// - Invisible elements are dropped entirely: the AI sees only what you see,
//   which also removes the classic hidden-text prompt-injection channel.
// - Detected secrets are replaced by format-preserving synthetic values
//   (or typed placeholders), consistently across every field, the page
//   title, the URL and the task itself.
// - Text that looks like a prompt injection is quarantined.

import { scanText } from "./patterns.js";
import { categoryOf, methodOf } from "./taxonomy.js";

export const AI_FIELDS = ["id", "tag", "role", "type", "label", "placeholder", "text", "value"];
const TEXT_FIELDS = ["text", "value", "label", "placeholder"];

// Port of core/sanitize/injection.py.
const INJECTION_PATTERNS = [
  ["instruction_override", /\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)\b/i],
  ["instruction_override", /\bdisregard\s+(all\s+)?(previous|prior|system)\s+instructions?\b/i],
  ["system_prompt_extraction", /\b(reveal|print|show|disclose|leak)\b.{0,60}\b(system prompt|hidden prompt|secret instructions)\b/i],
  ["secret_exfiltration", /\b(send|transmit|upload|exfiltrate|forward)\b.{0,80}\b(passwords?|credentials?|api keys?|card numbers?|secrets?|tokens?)\b/i],
  ["concealment", /\b(do not tell|don't tell|hide this from|without informing)\b/i],
  ["role_override", /\byou are now\s+(an?\s+)?(unrestricted|different|new)\s+(ai|assistant|agent)\b/i],
];

export const INJECTION_REASONS = {
  instruction_override: "Tries to override the agent's instructions.",
  system_prompt_extraction: "Tries to extract the agent's hidden instructions.",
  secret_exfiltration: "Asks the agent to send credentials or secrets somewhere.",
  concealment: "Asks the agent to hide its actions from you.",
  role_override: "Tries to redefine who the agent is.",
};

export function detectInjection(text) {
  if (typeof text !== "string" || !text) return [];
  return INJECTION_PATTERNS.filter(([, re]) => re.test(text)).map(([category]) => category);
}

export const QUARANTINE = "[QUARANTINED: possible prompt injection]";

// For the local "you see" column: enough to recognise the value, not to copy it.
export function mask(value) {
  if (value.length <= 4) return "•".repeat(value.length);
  return "•".repeat(Math.min(value.length - 4, 12)) + value.slice(-4);
}

// --- Task credentials (port of core/guard/canary.py:sanitize_task_credentials)

export class AmbiguousCredentialTask extends Error {
  constructor() {
    super("The task contains a credential that cannot be safely separated from the text.");
  }
}

const CREDENTIAL_RE =
  /\b(password|passwd|pwd|passcode|passphrase|pin|secret|api[_ -]?key|token|authorization|credential)\b\s*(?:(?:is)\s+|[:=]\s*|\s+)([^\s,;]+)/gi;
const NON_VALUE = new Set(["field", "input", "box", "form", "settings", "manager", "reset", "change", "entry", "in", "my", "the", "your"]);

/** Returns the credential values in `task`; throws when a label is followed by ambiguous prose. */
export function taskCredentials(task) {
  const values = [];
  for (const m of task.matchAll(CREDENTIAL_RE)) {
    const candidate = m[2].replace(/[.!?)\]}]+$/, "");
    if (!candidate || NON_VALUE.has(candidate.toLowerCase())) continue;
    const valueStart = m.index + m[0].length - m[2].length;
    const remainder = task.slice(valueStart + candidate.length).trimStart();
    if (remainder && !/^[.!?,;]/.test(remainder)) {
      const first = remainder.split(/\s+/, 1)[0].toLowerCase().replace(/^[.,!?;:]+|[.,!?;:]+$/g, "");
      if (!["to", "then", "please"].includes(first)) throw new AmbiguousCredentialTask();
    }
    values.push(candidate);
  }
  return values;
}

// -----------------------------------------------------------------------------

function replaceSpans(text, spans) {
  // spans: [{start, end, replacement}] — apply right to left, skip overlaps.
  let result = text;
  let floor = Infinity;
  for (const s of [...spans].sort((a, b) => b.start - a.start)) {
    if (s.end > floor) continue;
    result = result.slice(0, s.start) + s.replacement + result.slice(s.end);
    floor = s.start;
  }
  return result;
}

function replaceAll(text, substitutions) {
  let result = text;
  for (const [real, fake] of substitutions) result = result.split(real).join(fake);
  return result;
}

const TEXT_TAGS = new Set(["p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "blockquote", "td", "th", "dt", "dd", "svg"]);

// Original text with every protected span masked: what you see, minus the
// secrets, for the side-by-side view. Never leaves the panel.
function maskSpans(text, spans) {
  let result = text;
  for (const { start, end } of [...spans].sort((a, b) => b.start - a.start)) {
    result = result.slice(0, start) + mask(text.slice(start, end)) + result.slice(end);
  }
  return result;
}

export const DEFAULT_SANITIZE_OPTIONS = Object.freeze({
  task: "",
  dropInvisible: true,
  quarantineInjections: true,
});

/**
 * @param snapshot   {url, title, elements[]} from the content script
 * @param detections output of detect(snapshot)
 * @param vault      SyntheticVault for this task
 * @param options    {task, dropInvisible, quarantineInjections}
 * @returns {aiView, inventory, rows, injections, quarantined, hiddenDropped}
 *   aiView is the only thing that may leave the extension. inventory holds
 *   real values and must stay local; rows only hold masked values.
 */
export function sanitizeSnapshot(snapshot, detections, vault, options = {}) {
  const { task, dropInvisible, quarantineInjections } = { ...DEFAULT_SANITIZE_OPTIONS, ...options };
  const realToFake = new Map();
  const rows = [];
  const fields = new Map(); // one display row per element field
  const injections = [];
  let hiddenDropped = 0;

  const register = (type, real) => {
    if (!real) return null;
    const fake = vault.substitute(type, real);
    if (!realToFake.has(real)) realToFake.set(real, fake);
    return realToFake.get(real);
  };

  const byElement = new Map();
  for (const d of detections) {
    if (!byElement.has(d.elementId)) byElement.set(d.elementId, []);
    byElement.get(d.elementId).push(d);
  }

  const kept = [];
  for (const el of snapshot.elements) {
    const label = el.label || el.name || el.placeholder || el.domId || (TEXT_TAGS.has(el.tag) ? "Page text" : el.tag);
    const injectedFields = TEXT_FIELDS.filter((f) => detectInjection(el[f]).length);
    const injection = injectedFields.length
      ? {
          id: el.id, label, hidden: !el.visible, fields: injectedFields,
          categories: [...new Set(injectedFields.flatMap((f) => detectInjection(el[f])))],
          quarantined: false, reachedAI: false, preview: "",
          sourceText: injectedFields.map((f) => el[f]).join(" "),
        }
      : null;

    if (!el.visible && dropInvisible) {
      hiddenDropped++;
      if (injection) injections.push(injection);
      continue;
    }

    const out = {};
    for (const key of AI_FIELDS) out[key] = el[key] ?? (key === "role" || key === "type" ? null : "");

    for (const field of TEXT_FIELDS) {
      const original = el[field] || "";
      if (!original) continue;
      const spans = [];
      for (const d of byElement.get(el.id) || []) {
        if (d.field !== field) continue;
        let [start, end] = d.span ?? [0, original.length];
        if (!(start >= 0 && end > start && end <= original.length)) {
          [start, end] = [0, original.length]; // malformed span: protect the whole field
        }
        const real = original.slice(start, end);
        const replacement = register(d.type, real);
        spans.push({ start, end, replacement });
        rows.push({
          id: el.id, field, label, type: d.type,
          category: categoryOf(d.type, real),
          method: methodOf(d),
          action: replacement.startsWith("[REDACTED:") ? "redacted" : "replaced",
          masked: mask(real),
          hidden: !el.visible,
        });
      }
      if (spans.length) {
        fields.set(`${el.id} ${field}`, {
          id: el.id, field, label, hidden: !el.visible, original, spans,
          types: [...new Set(rows.filter((r) => r.id === el.id && r.field === field).map((r) => r.type))],
        });
      }
      out[field] = replaceSpans(original, spans);
    }

    if (injection) {
      injection.quarantined = quarantineInjections;
      // Every field that carried instructions is replaced, including form
      // values (e.g. a support-chat textarea), not just visible text.
      if (quarantineInjections) for (const f of injectedFields) out[f] = QUARANTINE;
      injections.push(injection);
    }
    kept.push({ el, out });
  }

  // Task text goes through the same detectors, plus credential assignments.
  for (const hit of scanText(task)) register(hit.type, task.slice(hit.span[0], hit.span[1]));
  for (const value of taskCredentials(task)) register("CREDENTIAL", value);

  // Global pass: a secret detected in one place is replaced everywhere.
  const substitutions = [...realToFake].sort((a, b) => b[0].length - a[0].length);
  const elements = kept.map(({ out }) => {
    for (const field of TEXT_FIELDS) out[field] = replaceAll(out[field] || "", substitutions);
    return out;
  });

  let pageUrl = "";
  try {
    const u = new URL(snapshot.url);
    pageUrl = u.origin + u.pathname; // query strings and fragments often carry tokens/PII
  } catch {
    pageUrl = "";
  }

  const aiView = {
    url: replaceAll(pageUrl, substitutions),
    title: replaceAll(snapshot.title || "", substitutions),
    task: replaceAll(task, substitutions),
    elements,
  };

  // Local-only display data: "AI sees" column and injection previews.
  const outById = new Map(elements.map((e) => [e.id, e]));
  for (const row of rows) row.after = outById.get(row.id)?.[row.field] ?? "(withheld: invisible element)";
  const maskedSubstitutions = substitutions.map(([real]) => [real, mask(real)]);
  const fieldRows = [...fields.values()].map(({ original, spans, ...f }) => {
    const fieldDetections = rows.filter((r) => r.id === f.id && r.field === f.field);
    return {
      ...f,
      youSee: replaceAll(maskSpans(original, spans), maskedSubstitutions),
      after: outById.get(f.id)?.[f.field] ?? "(withheld: invisible element)",
      categories: [...new Set(fieldDetections.map((r) => r.category))],
      methods: [...new Set(fieldDetections.map((r) => r.method))],
      actions: [...new Set(fieldDetections.map((r) => r.action))],
    };
  });
  const aiText = JSON.stringify(aiView);
  for (const inj of injections) {
    const sanitizedText = replaceAll(inj.sourceText, substitutions);
    inj.reachedAI = sanitizedText.length > 0 && aiText.includes(JSON.stringify(sanitizedText).slice(1, -1));
    inj.preview = sanitizedText.length > 160 ? `${sanitizedText.slice(0, 157)}…` : sanitizedText;
    delete inj.sourceText;
  }

  return {
    aiView,
    inventory: [...realToFake.keys()],
    rows,
    fields: fieldRows,
    injections,
    // Kept for callers of the earlier API.
    quarantined: injections.filter((i) => i.quarantined || i.hidden),
    hiddenDropped,
  };
}
