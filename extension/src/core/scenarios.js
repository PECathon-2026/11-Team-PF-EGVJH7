// PS-004 evaluation scenarios, run against the controlled pages in
// testlab/pages (synthetic test data only). Each scenario lists the values
// the page contains and what PrivacyLens must do with them; evaluateScan()
// compares that with what the real pipeline actually produced.

import { containsSecret, validateOutgoing } from "./egress.js";
import { luhnOk, scanText } from "./patterns.js";
import { mask } from "./sanitize.js";

export const SCENARIOS = [
  {
    id: "checkout",
    title: "E-commerce checkout",
    page: "checkout.html",
    task: "Complete the checkout and pay",
    summary: "Card, CVV, email and address are replaced; the Pay button needs your approval; a payload with the real card is blocked.",
    expected: [
      { type: "CARD", value: "4111 1111 1111 1111", represent: "luhn-synthetic" },
      { type: "CARD", value: "123", represent: "synthetic" },
      { type: "EMAIL", value: "test.user@example.com", represent: "synthetic" },
      { type: "ADDRESS", value: "42 MG Road, Bengaluru", represent: "synthetic" },
    ],
    dynamic: ["payApproval", "tamper"],
  },
  {
    id: "login",
    title: "Authentication",
    page: "login.html",
    task: "Sign in to my account. My password is hunter2-secret",
    summary: "Password and OTP are redacted, email is replaced, and a password typed into the task itself never reaches the AI.",
    expected: [
      { type: "EMAIL", value: "alice@example.com", represent: "synthetic" },
      { type: "PASSWORD", value: "hunter2-secret", represent: "redacted" },
      { type: "OTP", value: "482913", represent: "redacted" },
    ],
    dynamic: ["taskCredential", "tamper"],
  },
  {
    id: "support",
    title: "Customer support",
    page: "support.html",
    task: "Summarise the customer's issue",
    summary: "Emails and Indian phone numbers in chat messages are replaced; visible and hidden prompt injections never reach the AI.",
    expected: [
      { type: "EMAIL", value: "john.doe@example.com", represent: "synthetic" },
      { type: "PHONE", value: "+91 9876543210", represent: "synthetic" },
      { type: "PHONE", value: "9876543210", represent: "synthetic" },
      { type: "PHONE", value: "+91 98765 43210", represent: "synthetic" },
    ],
    dynamic: ["injections"],
  },
  {
    id: "video",
    title: "Video conferencing",
    page: "video.html",
    task: "Who is in this call?",
    summary: "Participant names and emails are replaced for the AI; the video privacy shield blurs the video feed, names and emails on the page. Video frames are never sent to the AI. Individual faces are not detected: the shield blurs whole frames.",
    expected: [
      { type: "PERSON", value: "Alice Smith", represent: "synthetic" },
      { type: "EMAIL", value: "alice.smith@example.com", represent: "synthetic" },
    ],
    unsupported: [
      { name: "Per-face detection and redaction", reason: "There is no face-detection model. The shield blurs entire video/canvas frames instead, and frames are never captured or sent to the AI." },
    ],
    dynamic: ["tamper", "videoShield"],
  },
  {
    id: "dev",
    title: "Developer settings",
    page: "dev.html",
    task: "Check whether all integrations are configured",
    summary: "API keys, tokens and IPs are redacted; payloads containing a real or an unregistered key are blocked.",
    expected: [
      { type: "API_KEY", value: "sk-proj-abc123def456ghi789jkl012", represent: "redacted" },
      { type: "API_KEY", value: "AKIAIOSFODNN7EXAMPLE", represent: "redacted" },
      { type: "API_KEY", value: "ghp_1234567890abcdefghijABCDEFGHIJ123456", represent: "redacted" },
      { type: "API_KEY", value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_share_this_token", represent: "redacted" },
      { type: "IP", value: "192.168.1.105", represent: "redacted" },
    ],
    dynamic: ["tamper", "secondOpinion"],
  },
];

const check = (name, expected, actual, passed, evidence = "") => ({
  name, expected, actual, status: passed ? "pass" : "fail", evidence,
});

/** Real substrings that P2 flagged, keyed by element. Stays local. */
function detectedValues(snapshot, detections) {
  const byId = new Map(snapshot.elements.map((e) => [e.id, e]));
  return detections.map((d) => {
    const source = byId.get(d.elementId)?.[d.field] || "";
    return { type: d.type, real: d.span ? source.slice(d.span[0], d.span[1]) : source, elementId: d.elementId, field: d.field };
  });
}

/**
 * Compare a real scan of the scenario page with the scenario's expectations.
 * `scan` comes from orchestrator.scanPage(); `snapshot` is the raw snapshot.
 */
export function evaluateScan(scenario, snapshot, scan) {
  const checks = [];
  const found = detectedValues(snapshot, scan.detections);
  const aiView = scan.sanitized.aiView;

  for (const exp of scenario.expected) {
    const hit = found.find((f) => f.real === exp.value || f.real.includes(exp.value));
    checks.push(check(
      `Detect ${exp.type} ${mask(exp.value)}`,
      `Detected as ${exp.type}`,
      hit ? `Detected as ${hit.type}` : "Not detected",
      Boolean(hit),
    ));

    const leaked = containsSecret(aiView, exp.value);
    const outById = new Map(aiView.elements.map((e) => [e.id, e]));
    const shown = hit ? (outById.get(hit.elementId)?.[hit.field] ?? "") : "";
    let representOk = !leaked;
    let expectedText = "Real value absent from AI view";
    if (exp.represent === "redacted") {
      representOk &&= /\[REDACTED:/.test(shown);
      expectedText = "Placeholder [REDACTED:…]";
    } else if (exp.represent === "luhn-synthetic") {
      const digits = shown.replace(/\D/g, "");
      representOk &&= digits.length >= 13 && luhnOk(digits);
      expectedText = "Different, Luhn-valid synthetic card";
    } else if (exp.represent === "synthetic") {
      representOk &&= shown.length > 0 && !shown.startsWith("[REDACTED:");
      expectedText = "Format-preserving synthetic value";
    }
    checks.push(check(
      `Sanitize ${exp.type} ${mask(exp.value)}`,
      expectedText,
      leaked ? "REAL VALUE PRESENT in AI view" : `AI sees "${shown || "(no field)"}"`,
      representOk,
    ));
  }

  checks.push(check(
    "Outgoing request passes the egress firewall",
    "Allowed (contains only sanitized data)",
    scan.egress.ok ? "Allowed" : `Blocked: ${scan.egress.reasons[0]}`,
    scan.egress.ok,
  ));
  checks.push(check("Honeytoken self-check", "Planted decoy removed", scan.honeytokenOk ? "Removed" : "SURVIVED", scan.honeytokenOk));

  const dyn = scenario.dynamic || [];
  if (dyn.includes("tamper") && scenario.expected.length) {
    const tampered = structuredClone(aiView);
    tampered.elements.push({ id: "tamper", tag: "p", text: scenario.expected[0].value });
    const v = validateOutgoing(tampered, scan.inventory, { allowedSynthetic: scan.allowedSynthetic });
    checks.push(check(
      "Unsafe outgoing payload is blocked",
      "Payload with a real value is blocked (fail-closed)",
      v.ok ? "ALLOWED" : `Blocked: ${v.reasons[0]}`,
      !v.ok,
      `Re-inserted ${mask(scenario.expected[0].value)} into the request`,
    ));
  }
  if (dyn.includes("secondOpinion")) {
    const unknown = "sk-" + "Z".repeat(30);
    const tampered = { ...aiView, elements: [...aiView.elements, { id: "x", tag: "p", text: unknown }] };
    const v = validateOutgoing(tampered, scan.inventory, { allowedSynthetic: scan.allowedSynthetic });
    checks.push(check(
      "Second-opinion scan catches an unregistered key",
      "Blocked even though the key is not in the inventory",
      v.ok ? "ALLOWED" : `Blocked: ${v.reasons[0]}`,
      !v.ok && scanText(unknown).length > 0,
    ));
  }
  if (dyn.includes("taskCredential")) {
    const leaked = containsSecret(aiView.task, "hunter2-secret");
    // The same password also sits in the page's password field, so it may be
    // registered as PASSWORD before the task is scanned; either placeholder is
    // a correct redaction. What matters: the real value is gone, a placeholder
    // stands where it was.
    checks.push(check(
      "Password typed into the task is redacted",
      "Task reaches the AI with the password replaced by [REDACTED:…]",
      leaked ? "REAL PASSWORD PRESENT in task" : `Task sent as "${aiView.task}"`,
      !leaked && /My password is \[REDACTED:(CREDENTIAL|PASSWORD)\]$/.test(aiView.task),
    ));
  }
  if (dyn.includes("injections")) {
    const visible = scan.sanitized.injections.filter((i) => !i.hidden);
    const hidden = scan.sanitized.injections.filter((i) => i.hidden);
    checks.push(check(
      "Visible prompt injection quarantined",
      "At least one, none reach the AI",
      `${visible.length} found, ${visible.filter((i) => i.reachedAI).length} reached the AI`,
      visible.length > 0 && visible.every((i) => i.quarantined && !i.reachedAI),
    ));
    checks.push(check(
      "Hidden prompt injection withheld",
      "At least one, none reach the AI",
      `${hidden.length} found, ${hidden.filter((i) => i.reachedAI).length} reached the AI`,
      hidden.length > 0 && hidden.every((i) => !i.reachedAI),
    ));
  }

  for (const u of scenario.unsupported || []) {
    const actual = u.value
      ? (containsSecret(aiView, u.value) ? "Sent to the AI unchanged" : "Not present in AI view")
      : "Not implemented";
    checks.push({ name: u.name, expected: "Not supported", actual, status: "unsupported", evidence: u.reason });
  }
  return checks;
}

export function verdictOf(checks) {
  if (checks.some((c) => c.status === "fail")) return "fail";
  if (checks.some((c) => c.status === "unsupported")) return "partial";
  return "pass";
}
