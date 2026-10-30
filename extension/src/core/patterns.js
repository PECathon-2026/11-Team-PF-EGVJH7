// P2 detectors: regex candidates confirmed by checksum math.
// Port of core/detect/patterns.py and core/detect/validators.py.
// tests/test_extension_parity.py checks these against the Python originals.

// Python's \w and \b are Unicode-aware; JavaScript's are ASCII-only even
// with the u flag, so spell both out.
const W = "\\p{L}\\p{N}_";
const B = `(?:(?<=[${W}])(?![${W}])|(?<![${W}])(?=[${W}]))`;
const unicodeRe = (source) => new RegExp(source.replaceAll("\\b", B), "gu");

export function luhnOk(digits) {
  if (!/^\d+$/.test(digits)) return false;
  let total = 0;
  [...digits].reverse().forEach((ch, i) => {
    let n = Number(ch);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    total += n;
  });
  return total % 10 === 0;
}

export const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
export const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
export const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

export function verhoeffOk(digits) {
  if (!/^\d{12}$/.test(digits)) return false;
  let c = 0;
  [...digits].reverse().forEach((ch, i) => {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][Number(ch)]];
  });
  return c === 0;
}

function* matches(re, text) {
  for (const m of text.matchAll(re)) yield [m.index, m.index + m[0].length, m[0]];
}

const CARD_RE = unicodeRe(String.raw`\b(?:\d[ -]?){12,18}\d\b`);
export function findCards(text) {
  const out = [];
  for (const hit of matches(CARD_RE, text)) {
    const digits = hit[2].replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhnOk(digits)) out.push(hit);
  }
  return out;
}

const AADHAAR_RE = unicodeRe(String.raw`\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b`);
export function findAadhaar(text) {
  return [...matches(AADHAAR_RE, text)].filter((hit) => verhoeffOk(hit[2].replace(/\s/g, "")));
}

const PAN_RE = unicodeRe(String.raw`\b[A-Z]{5}[0-9]{4}[A-Z]\b`);
export const findPan = (text) => [...matches(PAN_RE, text)];

const EMAIL_RE = new RegExp(`[${W}.+-]+@[${W}-]+\\.[${W}.-]+`, "gu");
export const findEmail = (text) => [...matches(EMAIL_RE, text)];

const PHONE_RE = new RegExp(
  `(?<![${W}])(?:\\+\\d{1,3}[\\s().-]*)?(?:\\(?\\d{2,4}\\)?[\\s().-]*)?` +
    `\\d{3,4}[\\s().-]*\\d{3,4}(?![${W}\\s().-]*\\d)`,
  "gu",
);
// Indian mobile numbers ("+91 98765 43210", "98765-43210", "09876543210"),
// which the generic pattern cannot split 5+5. Mirrors _IN_MOBILE_RE.
const IN_MOBILE_RE = new RegExp(
  `(?<![${W}+])(?:(?:\\+|00)91[ -]?|0)?[6-9][0-9]{4}[ -]?[0-9]{5}(?![${W}])`,
  "gu",
);

// Reject matches glued to more digits, e.g. inside card numbers.
function isolated(text, start, end) {
  if (/\d[\s().-]*$/u.test(text.slice(0, start))) return false;
  return !/^[\s().-]*\d/u.test(text.slice(end));
}

export function findPhone(text) {
  const found = [];
  for (const [start, end, raw] of matches(PHONE_RE, text)) {
    if (!isolated(text, start, end)) continue;
    const digits = raw.replace(/\D/g, "");
    const formatted = /[+().\s-]/.test(raw);
    if (
      digits.length >= 10 && digits.length <= 15 &&
      (formatted || digits.length === 10) &&
      (digits.length !== 10 || "23456789".includes(digits[0]))
    ) {
      found.push([start, end, raw]);
    }
  }
  for (const hit of matches(IN_MOBILE_RE, text)) {
    if (isolated(text, hit[0], hit[1])) found.push(hit);
  }

  // Merge both matchers: earliest start wins, then the longest span.
  const out = [];
  for (const hit of found.sort((a, b) => a[0] - b[0] || b[1] - a[1])) {
    if (out.length && hit[0] < out.at(-1)[1]) continue;
    out.push(hit);
  }
  return out;
}

const OTP_DIGITS_RE = unicodeRe(String.raw`\b\d{4,8}\b`);
const OTP_CONTEXT = /(otp|one[-\s]?time|verification|2fa|code)/i;
export const findOtp = (text) => (OTP_CONTEXT.test(text) ? [...matches(OTP_DIGITS_RE, text)] : []);

const API_KEY_RE = unicodeRe(
  String.raw`\b(sk-[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b`,
);
export const findApiKeys = (text) => [...matches(API_KEY_RE, text)];

const IP_RE = unicodeRe(
  String.raw`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
);
export const findIps = (text) => [...matches(IP_RE, text)];

export const FINDERS = [
  ["CARD", findCards], ["AADHAAR", findAadhaar], ["PAN", findPan],
  ["EMAIL", findEmail], ["PHONE", findPhone], ["OTP", findOtp],
  ["API_KEY", findApiKeys], ["IP", findIps],
];

export function scanText(text) {
  const out = [];
  for (const [type, fn] of FINDERS) {
    for (const [start, end] of fn(text)) out.push({ type, source: "regex", span: [start, end] });
  }
  return out;
}
