// P4 action policy. Port of core/agent/validator.py, core/browser/navigation.py
// and the consequential-action rules from core/browser/executor.py, extended
// with a real human-approval path instead of a permanent block.

const RISKY_OPERATIONS =
  /(?:^|[^a-z0-9])(?:delete|remove|submit|purchase|buy|transfer|pay|logout|logoff|cancel|destroy|deactivate|withdraw|refund)(?:$|[^a-z0-9])/i;
const RISKY_QUERY_KEYS = new Set(["action", "operation", "op", "intent", "command", "cmd", "do", "method"]);

export const SENSITIVE_BUTTON_WORDS = [
  "pay", "purchase", "buy", "checkout", "transfer", "delete",
  "remove account", "submit order", "confirm payment", "place order",
  "send money", "withdraw", "sign out", "log out",
];

export const ACTION_TYPES = new Set(["click", "type", "select", "scroll", "navigate", "done"]);
const ACTION_KEYS = new Set(["type", "element_id", "text", "url", "reason"]);

export class PolicyError extends Error {}

export function validateNavigationUrl(url) {
  if (typeof url !== "string" || !url || [...url].some((c) => c.charCodeAt(0) <= 32 || c.charCodeAt(0) === 127)) {
    throw new PolicyError("Navigation URL is malformed.");
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new PolicyError("Navigation URL is malformed.");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
    throw new PolicyError("Navigation is restricted to HTTP(S) URLs with a hostname.");
  }
  if (parsed.username || parsed.password) {
    throw new PolicyError("Navigation URL contains unsupported authority data.");
  }
  const params = [...parsed.searchParams];
  const components = [parsed.pathname, parsed.hash.slice(1), ...params.flat()];
  for (const component of components) {
    let decoded = component;
    for (let i = 0; i < 3; i++) {
      let next;
      try {
        next = decodeURIComponent(decoded);
      } catch {
        break;
      }
      if (next === decoded) break;
      decoded = next;
    }
    decoded = decoded.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_-]/g, " ");
    if (RISKY_OPERATIONS.test(decoded)) throw new PolicyError("Potentially consequential navigation is blocked.");
  }
  for (const [key, value] of params) {
    if (RISKY_QUERY_KEYS.has(key.toLowerCase()) && value.trim()) {
      throw new PolicyError("Potentially consequential navigation is blocked.");
    }
  }
  return url;
}

export function isConsequential(element) {
  const description = [element.text, element.label, element.name, element.value]
    .filter(Boolean).join(" ").toLowerCase();
  if (SENSITIVE_BUTTON_WORDS.some((w) => description.includes(w))) return true;
  const type = (element.type || "").toLowerCase();
  return ["submit", "image"].includes(type) || (element.tag === "button" && element.formSubmit === true);
}

const FINANCIAL_WORDS = ["pay", "purchase", "buy", "checkout", "confirm payment", "place order", "send money", "transfer", "withdraw"];
const DESTRUCTIVE_WORDS = ["delete", "remove account", "cancel", "deactivate"];

/** Risk classification shown on approval cards. */
export function classifyRisk(element, restoredTypes = []) {
  const description = [element?.text, element?.label, element?.name, element?.value]
    .filter(Boolean).join(" ").toLowerCase();
  if (restoredTypes.includes("CARD") || FINANCIAL_WORDS.some((w) => description.includes(w))) {
    return { level: "critical", label: "Critical · financial transaction" };
  }
  if (restoredTypes.includes("AADHAAR") || restoredTypes.includes("PAN")) {
    return { level: "critical", label: "Critical · government identity document" };
  }
  if (DESTRUCTIVE_WORDS.some((w) => description.includes(w))) {
    return { level: "high", label: "High · irreversible action" };
  }
  if (element && isConsequential(element)) return { level: "high", label: "High · form submission" };
  return { level: "medium", label: "Medium · protected data entry" };
}

/** Strictly parse an untrusted model response into an action. */
export function parseAction(candidate) {
  if (typeof candidate === "string") {
    const stripped = candidate.trim().replace(/^```(?:json)?\s*|\s*```$/g, "");
    try {
      candidate = JSON.parse(stripped);
    } catch {
      throw new PolicyError("Agent response is not valid JSON.");
    }
  }
  if (Array.isArray(candidate) && candidate.length === 1) candidate = candidate[0];
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new PolicyError("Agent response must be a JSON object.");
  }
  for (const key of Object.keys(candidate)) {
    if (!ACTION_KEYS.has(key)) throw new PolicyError("Agent response contains unsupported fields.");
  }
  if (!ACTION_TYPES.has(candidate.type)) throw new PolicyError("Unsupported action type.");
  for (const key of ["element_id", "text", "url", "reason"]) {
    if (candidate[key] != null && typeof candidate[key] !== "string") {
      throw new PolicyError(`Field ${key} must be a string.`);
    }
  }
  // Models often send "" for fields that do not apply; treat that as absent
  // so a valid scroll/done is not rejected for "extra payload". (An empty
  // string is still kept for `type` actions, where clearing a field is valid.)
  const blankToNull = (v) => (v === "" ? null : v ?? null);
  return {
    type: candidate.type,
    element_id: blankToNull(candidate.element_id),
    text: candidate.type === "type" ? candidate.text ?? null : blankToNull(candidate.text),
    url: blankToNull(candidate.url),
    reason: (candidate.reason ?? "").slice(0, 300),
  };
}

/**
 * Decide whether an action may run.
 * @returns {{ok: boolean, needsApproval: boolean, reason: string}}
 */
export function validateAction(action, aiView, rawById) {
  const deny = (reason) => ({ ok: false, needsApproval: false, reason });
  const allow = (needsApproval = false, reason = "") => ({ ok: true, needsApproval, reason });

  if (action.type === "done") {
    return action.element_id || action.url || action.text != null ? deny("Done action contains extra payload.") : allow();
  }
  if (action.type === "scroll") {
    return action.element_id || action.url || action.text != null ? deny("Scroll action contains unsupported payload.") : allow();
  }
  if (action.type === "navigate") {
    try {
      validateNavigationUrl(action.url);
    } catch (err) {
      return deny(err.message);
    }
    return action.element_id || action.text != null ? deny("Navigate action contains unsupported payload.") : allow();
  }

  if (!action.element_id) return deny("Action is missing an element ID.");
  const element = aiView.elements.find((e) => e.id === action.element_id);
  const raw = rawById.get(action.element_id);
  if (!element || !raw) return deny("Element does not exist in the sanitized view.");
  if (raw.attrs?.disabled) return deny("Element is disabled.");

  if (action.type === "click") {
    if (action.text != null || action.url) return deny("Click action contains unsupported payload.");
    if (isConsequential(raw)) return allow(true, "Consequential control (payment, deletion or submission).");
    return allow();
  }
  if (action.type === "type") {
    if (!["input", "textarea"].includes(raw.tag)) return deny("Typing is restricted to input and textarea elements.");
    if (["password", "hidden"].includes((raw.type || "").toLowerCase())) return deny("Password and hidden inputs are never typed by the agent.");
    if (raw.attrs?.readonly) return deny("Element is read-only.");
    if (action.text == null || action.url) return deny("Type action requires text only.");
    return allow();
  }
  if (action.type === "select") {
    if (raw.tag !== "select" || action.text == null || action.url) return deny("Select action does not match its target.");
    return allow();
  }
  return deny("Unsupported action.");
}
