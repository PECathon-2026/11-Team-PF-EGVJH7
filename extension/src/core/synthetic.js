// Format-preserving synthetic values. Unlike core/detect/synthetic.py this
// covers AADHAAR and PAN too, uses a CSPRNG, and never reuses the real BIN.
//
// A SyntheticVault lives only in extension memory for one task. The AI sees
// synthetic values; the vault maps them back to real values at execution time.

import { luhnOk, verhoeffOk, VERHOEFF_D, VERHOEFF_INV, VERHOEFF_P } from "./patterns.js";

const DIGITS = "0123456789";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";

function randomIndex(n) {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % n;
}
const pick = (alphabet) => alphabet[randomIndex(alphabet.length)];
const randomString = (alphabet, n) => Array.from({ length: n }, () => pick(alphabet)).join("");

// Reapply the original separators (spaces, dashes) to a new digit string.
function reshape(template, digits) {
  let i = 0;
  return template.replace(/\d/g, () => digits[i++]);
}

export function syntheticCard(real) {
  const digits = real.replace(/\D/g, "");
  if (digits.length <= 4) {
    // CVV / CVC: same length, different value.
    let fake;
    do fake = randomString(DIGITS, digits.length || 3);
    while (fake === digits);
    return fake;
  }
  if (digits.length < 13 || digits.length > 19) return null;
  // Visa-shaped "4" prefix + random body + Luhn check digit. The real BIN
  // (issuer prefix) is deliberately not reused: it identifies the bank.
  for (;;) {
    const partial = "4" + randomString(DIGITS, digits.length - 2);
    const check = [...DIGITS].find((c) => luhnOk(partial + c));
    const fake = partial + check;
    if (fake.slice(0, 6) !== digits.slice(0, 6) && fake !== digits) return reshape(real, fake);
  }
}

export function verhoeffCheckDigit(payload) {
  let c = 0;
  [...payload].reverse().forEach((ch, i) => {
    c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][Number(ch)]];
  });
  return String(VERHOEFF_INV[c]);
}

export function syntheticAadhaar(real) {
  const payload = pick("23456789") + randomString(DIGITS, 10);
  const digits = payload + verhoeffCheckDigit(payload);
  return verhoeffOk(digits) ? reshape(real, digits) : null;
}

export function syntheticPan() {
  return randomString(UPPER, 5) + randomString(DIGITS, 4) + pick(UPPER);
}

export function syntheticEmail() {
  return `user.${randomString(LOWER + DIGITS, 8)}@example.com`;
}

export function syntheticPhone(real) {
  // Keep the country / trunk prefix ("+91 ", "0091-", "+1 ", leading "0") so
  // the AI still knows which country the number is from; randomise the rest.
  const prefix = /^(?:(?:\+|00)91[ -]?|\+\d{1,3}[ -]|0(?=[6-9]))/.exec(real)?.[0] ?? "";
  const rest = real.slice(prefix.length);
  const n = rest.replace(/\D/g, "").length;
  if (!n) return null;
  return prefix + reshape(rest, pick("6789") + randomString(DIGITS, n - 1));
}

export function syntheticAddress() {
  return `${10 + randomIndex(990)} Synthetic Avenue, Test City`;
}

const FIRST_NAMES = ["Aarav", "Diya", "Kabir", "Meera", "Rohan", "Sara", "Vikram", "Zoya"];
const LAST_NAMES = ["Sharma", "Iyer", "Khan", "Patel", "Reddy", "Singh", "Das", "Nair"];

export function syntheticName() {
  return `${pick(FIRST_NAMES)} ${pick(LAST_NAMES)}`;
}

const GENERATORS = {
  CARD: syntheticCard,
  AADHAAR: syntheticAadhaar,
  PAN: syntheticPan,
  EMAIL: syntheticEmail,
  PHONE: syntheticPhone,
  ADDRESS: syntheticAddress,
  PERSON: syntheticName,
};

/**
 * A complete fake identity for filling forms when the user has not entered
 * their own details. Every value is synthetic test data (the card is a
 * Luhn-valid number in the "4" range, never a real account).
 */
export function syntheticIdentity() {
  const name = syntheticName();
  const handle = name.toLowerCase().replace(/[^a-z]+/g, ".") + randomString(DIGITS, 3);
  return {
    full_name: name,
    email: `${handle}@example.com`,
    phone: `+91 ${pick("6789")}${randomString(DIGITS, 4)} ${randomString(DIGITS, 5)}`,
    address: syntheticAddress(),
    username: handle,
    password: `Syn-${randomString(UPPER + LOWER + DIGITS, 6)}-${randomString(UPPER + LOWER + DIGITS, 6)}!`,
    card_number: syntheticCard("0000 0000 0000 0000"),
    card_expiry: `${String(1 + randomIndex(12)).padStart(2, "0")}/${30 + randomIndex(5)}`,
    cvv: randomString(DIGITS, 3),
  };
}

// High-impact types: restoring the real value into a page needs approval.
export const RESTORE_NEEDS_APPROVAL = new Set(["CARD", "AADHAAR", "PAN"]);

export const SYNTHETIC_TYPES = new Set(Object.keys(GENERATORS));

export class SyntheticVault {
  #realToFake = new Map();
  #fakeToReal = new Map();
  #fakeType = new Map();
  #reals = new Set();
  #redactTypes;

  /** @param redactTypes types to replace with a placeholder even when a synthetic generator exists */
  constructor({ redactTypes = [] } = {}) {
    this.#redactTypes = new Set(redactTypes);
  }

  // Returns a synthetic value, or a typed placeholder for secrets that must
  // never be imitated (passwords, OTPs, API keys).
  substitute(type, real) {
    const key = `${type}\u0000${real}`;
    if (this.#realToFake.has(key)) return this.#realToFake.get(key);
    this.#reals.add(real);

    const generator = this.#redactTypes.has(type) ? null : GENERATORS[type];
    let fake = null;
    for (let attempt = 0; generator && attempt < 20 && !fake; attempt++) {
      const candidate = generator(real);
      // Never hand out a value that is (or is inside) a real secret we know of.
      // (Containment is only meaningful for longer values; a CVV "123" would
      // otherwise veto innocent cards that happen to contain those digits.)
      const clashes = [...this.#reals].some((r) =>
        r === candidate || (r.length >= 6 && (r.includes(candidate) || candidate.includes(r))));
      if (candidate && !clashes && !this.#fakeToReal.has(candidate)) fake = candidate;
    }
    if (!fake) fake = `[REDACTED:${type}]`;

    this.#realToFake.set(key, fake);
    if (!fake.startsWith("[REDACTED:")) {
      this.#fakeToReal.set(fake, real);
      this.#fakeType.set(fake, type);
    }
    return fake;
  }

  get syntheticValues() {
    return [...this.#fakeToReal.keys()];
  }

  // Replace every synthetic value inside `text` with its real counterpart.
  // Reports which types were restored so callers can demand approval.
  // `restored` holds real values: callers may only show them masked.
  restore(text) {
    let result = text;
    const types = new Set();
    const restored = [];
    for (const fake of [...this.#fakeToReal.keys()].sort((a, b) => b.length - a.length)) {
      if (result.includes(fake)) {
        const real = this.#fakeToReal.get(fake);
        result = result.split(fake).join(real);
        types.add(this.#fakeType.get(fake));
        restored.push({ type: this.#fakeType.get(fake), real });
      }
    }
    return { text: result, restoredTypes: [...types], restored };
  }
}
