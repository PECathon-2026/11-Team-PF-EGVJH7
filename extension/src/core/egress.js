// P3 fail-closed egress firewall. Port of core/guard/egress.py with two
// additions: formatting variants of every secret, and a "second opinion"
// re-scan of the outgoing payload with the P2 detectors themselves.

import { scanText } from "./patterns.js";

// Types whose appearance in outgoing data is a leak unless it is one of our
// own synthetic values.
const NEVER_EGRESS = new Set(["CARD", "AADHAAR", "PAN", "API_KEY"]);

export function extractStrings(value, out = [], seen = new Set()) {
  if (typeof value === "string") {
    out.push(value);
  } else if (value === null || value === undefined || typeof value === "number" || typeof value === "boolean") {
    // Nothing to inspect.
  } else if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("Payload contains a cycle.");
    seen.add(value);
    for (const item of value) extractStrings(item, out, seen);
  } else if (Object.getPrototypeOf(value) === Object.prototype) {
    if (seen.has(value)) throw new Error("Payload contains a cycle.");
    seen.add(value);
    for (const [key, item] of Object.entries(value)) {
      out.push(key);
      extractStrings(item, out, seen);
    }
  } else {
    // Blobs, Maps, class instances, functions...: cannot prove they are safe.
    throw new Error(`Unsupported payload value type: ${Object.prototype.toString.call(value)}`);
  }
  return out;
}

// A secret plus the reformatted spellings a leak could take.
export function variants(secret) {
  const found = new Set([secret, secret.toLowerCase(), secret.toUpperCase()]);
  const compact = secret.replace(/[\s-]/g, "");
  if (/^\d+$/.test(compact)) {
    found.add(compact);
    found.add(compact.match(/.{1,4}/g).join("-"));
    found.add(compact.match(/.{1,4}/g).join(" "));
  }
  return [...found];
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Short secrets (e.g. a 3-digit CVV) only count as a whole token, otherwise
// "123" would match inside an unrelated synthetic card "4123 ...".
function occursIn(secret, text) {
  if (secret.length >= 6) return text.includes(secret);
  return new RegExp(`(?<![\\p{L}\\p{N}])${escapeRe(secret)}(?![\\p{L}\\p{N}])`, "u").test(text);
}

/** True when `secret` (in any of its variants) occurs anywhere in `payload`. */
export function containsSecret(payload, secret) {
  const strings = extractStrings(payload);
  return variants(secret).some((v) => strings.some((s) => occursIn(v, s)));
}

/**
 * Validate an outgoing payload. Fails closed when the inventory is missing,
 * empty or malformed, or when the payload cannot be fully inspected.
 * Reasons never contain secret values.
 */
export function validateOutgoing(payload, inventory, { allowedSynthetic = [] } = {}) {
  try {
    if (!Array.isArray(inventory) || inventory.length === 0) {
      throw new Error("Protected-value inventory is empty; refusing to send.");
    }
    if (inventory.some((v) => typeof v !== "string" || v === "")) {
      throw new Error("Protected-value inventory contains invalid entries.");
    }

    const strings = extractStrings(payload);
    const protectedValues = new Set(inventory.flatMap(variants));
    let leakCount = 0;
    for (const secret of protectedValues) {
      if (strings.some((s) => occursIn(secret, s))) leakCount++;
    }
    if (leakCount) {
      return { ok: false, reasons: ["Protected original value detected in outgoing payload."], leakCount };
    }

    // Blank out our own synthetic values before re-scanning: a synthetic card
    // can contain a substring that is itself a valid Aadhaar, for example.
    const allowed = [...new Set(allowedSynthetic)].sort((a, b) => b.length - a.length);
    for (const original of strings) {
      let s = original;
      for (const fake of allowed) s = s.split(fake).join("\u0000".repeat(fake.length));
      for (const hit of scanText(s)) {
        if (NEVER_EGRESS.has(hit.type)) {
          return {
            ok: false,
            reasons: [`Second-opinion scan found an unregistered ${hit.type} value.`],
            leakCount: 1,
          };
        }
      }
    }
    return { ok: true, reasons: [], leakCount: 0 };
  } catch (err) {
    return { ok: false, reasons: [String(err.message || err)], leakCount: 0 };
  }
}
