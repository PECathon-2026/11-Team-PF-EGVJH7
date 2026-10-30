// The autofill profile: the details the agent may type into forms.
//
// exposure:
//   "synthetic"  the AI sees a format-preserving stand-in; the real value is
//                swapped in on the page at execution time
//   "secret"     the AI never sees any value, only a reference; it asks for it
//                with {"secret_ref": "<key>"} and the extension types it
//   "plain"      not sensitive on its own (card expiry), shown as is

export const PROFILE_FIELDS = [
  { key: "full_name", label: "Full name", type: "PERSON", exposure: "synthetic" },
  { key: "email", label: "Email", type: "EMAIL", exposure: "synthetic" },
  { key: "phone", label: "Phone", type: "PHONE", exposure: "synthetic" },
  { key: "address", label: "Address", type: "ADDRESS", exposure: "synthetic" },
  { key: "username", label: "Username", type: "USERNAME", exposure: "secret" },
  { key: "password", label: "Password", type: "PASSWORD", exposure: "secret", approval: true },
  { key: "card_number", label: "Card number", type: "CARD", exposure: "synthetic" },
  { key: "card_expiry", label: "Card expiry (MM/YY)", type: null, exposure: "plain" },
  { key: "cvv", label: "CVV", type: "CARD", exposure: "secret", approval: true },
];

export const PROFILE_KEYS = new Set(PROFILE_FIELDS.map((f) => f.key));
export const fieldDef = (key) => PROFILE_FIELDS.find((f) => f.key === key);

/** The user's own values win; empty ones fall back to the synthetic identity. */
export function effectiveProfile(own = {}, synthetic = {}, useSynthetic = true) {
  const values = {};
  const source = {};
  for (const { key } of PROFILE_FIELDS) {
    const mine = typeof own[key] === "string" ? own[key].trim() : "";
    if (mine) {
      values[key] = mine;
      source[key] = "you";
    } else if (useSynthetic && synthetic[key]) {
      values[key] = synthetic[key];
      source[key] = "synthetic";
    }
  }
  return { values, source };
}

/**
 * Which profile field a form control asks for, from what the AI view shows
 * (type, label, placeholder). Returns null when unsure: the agent then
 * leaves the field alone.
 */
export function fieldKindOf(element) {
  const type = (element.type || "").toLowerCase();
  const hay = `${element.label || ""} ${element.placeholder || ""}`.toLowerCase();
  if (type === "password" || /pass(word|code|phrase)/.test(hay)) return "password";
  if (/\b(cvv|cvc|security code)\b/.test(hay)) return "cvv";
  if (/expir|mm ?\/ ?yy/.test(hay)) return "card_expiry";
  if (/card/.test(hay)) return "card_number";
  if (type === "email" || /e-?mail/.test(hay)) return "email";
  if (type === "tel" || /\b(phone|mobile)\b/.test(hay)) return "phone";
  if (/user ?name|login id/.test(hay)) return "username";
  if (/address/.test(hay)) return "address";
  if (/\bname\b/.test(hay)) return "full_name";
  return null;
}
