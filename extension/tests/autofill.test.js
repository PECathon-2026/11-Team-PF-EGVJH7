import { test } from "node:test";
import assert from "node:assert/strict";

import { mockAgent } from "../src/core/agent.js";
import { containsSecret } from "../src/core/egress.js";
import { runAgent } from "../src/core/orchestrator.js";
import { parseAction, validateAction } from "../src/core/policy.js";
import { effectiveProfile, fieldKindOf } from "../src/core/profile.js";
import { syntheticIdentity } from "../src/core/synthetic.js";
import { luhnOk } from "../src/core/patterns.js";

const REAL = { email: "priya.real@corp.test", password: "Real-Pa55word!", full_name: "Priya Real" };

test("form fields are matched to profile entries by type, label and placeholder", () => {
  const kind = (props) => fieldKindOf({ tag: "input", type: "text", label: "", placeholder: "", ...props });
  assert.equal(kind({ type: "password" }), "password");
  assert.equal(kind({ type: "email" }), "email");
  assert.equal(kind({ label: "Mobile number" }), "phone");
  assert.equal(kind({ label: "Full name" }), "full_name");
  assert.equal(kind({ label: "Username" }), "username");
  assert.equal(kind({ label: "Address" }), "address");
  assert.equal(kind({ label: "Card number" }), "card_number");
  assert.equal(kind({ placeholder: "MM/YY" }), "card_expiry");
  assert.equal(kind({ label: "CVV" }), "cvv");
  assert.equal(kind({ label: "Search products" }), null);
});

test("your own details win; the synthetic identity only fills gaps", () => {
  const synthetic = syntheticIdentity();
  const { values, source } = effectiveProfile({ email: REAL.email }, synthetic, true);
  assert.equal(values.email, REAL.email);
  assert.equal(source.email, "you");
  assert.equal(values.password, synthetic.password);
  assert.equal(source.password, "synthetic");
  assert.deepEqual(effectiveProfile({}, synthetic, false).values, {});
  assert.ok(luhnOk(synthetic.card_number.replace(/\D/g, "")));
});

test("secret_ref rules: passwords only by reference, with approval", () => {
  const view = { elements: [{ id: "p" }, { id: "e" }, { id: "b" }] };
  const raw = new Map([
    ["p", { id: "p", tag: "input", type: "password", attrs: {} }],
    ["e", { id: "e", tag: "input", type: "email", attrs: {} }],
    ["b", { id: "b", tag: "button", type: "button", text: "Go", attrs: {} }],
  ]);
  const check = (a) => validateAction(parseAction(JSON.stringify(a)), view, raw);
  assert.deepEqual(check({ type: "type", element_id: "p", secret_ref: "password", reason: "" }),
    { ok: true, needsApproval: true, reason: "Enters your password into the page." });
  assert.equal(check({ type: "type", element_id: "p", text: "guess", reason: "" }).ok, false);
  assert.equal(check({ type: "type", element_id: "p", secret_ref: "email", reason: "" }).ok, false);
  assert.equal(check({ type: "type", element_id: "e", secret_ref: "nope", reason: "" }).ok, false);
  assert.equal(check({ type: "type", element_id: "e", secret_ref: "username", reason: "" }).needsApproval, false);
  assert.equal(check({ type: "type", element_id: "e", secret_ref: "password", text: "x", reason: "" }).ok, false);
  assert.equal(check({ type: "click", element_id: "b", secret_ref: "password", reason: "" }).ok, false);
});

test("mock agent fills empty fields first, then submits, and only for form tasks", () => {
  const elements = [
    { id: "e1", tag: "input", type: "email", label: "Email", placeholder: "", value: "", text: "" },
    { id: "e2", tag: "input", type: "password", label: "Password", placeholder: "", value: "", text: "" },
    { id: "e3", tag: "button", type: "submit", label: "", placeholder: "", value: "", text: "Sign in" },
  ];
  const profile = { email: "user.x@example.com", password: '[SECRET: use secret_ref "password"]' };
  const req = (history) => ({ task: "Sign in to my account", url: "u", elements, profile, history });
  assert.deepEqual(mockAgent(req([])), { type: "type", element_id: "e1", text: "user.x@example.com", reason: "Fill email from your profile." });
  assert.deepEqual(mockAgent(req([{ type: "type", element_id: "e1", page: "u" }])),
    { type: "type", element_id: "e2", secret_ref: "password", reason: "Fill password from your profile." });
  assert.equal(mockAgent(req([{ element_id: "e1", page: "u" }, { element_id: "e2", page: "u" }])).element_id, "e3");
  // A search-style task never auto-fills personal details.
  assert.notEqual(mockAgent({ ...req([]), task: "Find the cheapest mouse" }).type, "type");
});

// --- Full sign-in through the real loop, against a simulated page ---------------

function signInPage() {
  const fields = { e1: "", e2: "" };
  let submitted = null;
  const snapshot = (n) => ({
    url: "https://shop.test/signin", title: "Sign in", snapshotId: `s${n}`,
    elements: [
      { id: "e1", tag: "input", type: "email", name: "email", label: "Email", placeholder: "", text: "", value: fields.e1, attrs: {}, visible: true },
      { id: "e2", tag: "input", type: "password", name: "password", label: "Password", placeholder: "", text: "", value: fields.e2, attrs: {}, visible: true },
      { id: "e3", tag: "button", type: "submit", name: null, label: "", placeholder: "", text: "Sign in", value: "", attrs: {}, visible: true, formSubmit: true },
    ],
  });
  let n = 0;
  const sent = [];
  const send = async (msg) => {
    sent.push(msg);
    if (msg.cmd === "snapshot") return { ok: true, snapshot: snapshot(++n) };
    if (msg.cmd === "execute" && msg.action.type === "type") fields[msg.action.element_id] = msg.action.text;
    if (msg.cmd === "execute" && msg.action.type === "click") submitted = { ...fields };
    return { ok: true };
  };
  return { send, sent, submitted: () => submitted };
}

test("sign-in with your real details: page gets them, the AI never does", async () => {
  const page = signInPage();
  const aiViews = [];
  const approvals = [];
  const result = await runAgent({
    task: "Sign in to my account", send: page.send,
    profile: REAL, profileSource: { email: "you", password: "you", full_name: "you" },
    ui: {
      event: (kind, data) => kind === "scan" && aiViews.push(data.aiView),
      requestApproval: async (card) => { approvals.push(card); return true; },
    },
  });

  assert.equal(result.status, "completed", result.message);
  assert.deepEqual(page.submitted(), { e1: REAL.email, e2: REAL.password });
  // Password entry and form submission each needed one approval.
  assert.deepEqual(approvals.map((a) => [a.action, a.risk.level]), [["type", "high"], ["click", "high"]]);
  assert.equal(approvals[0].uses[0].type, "PASSWORD");
  assert.equal(approvals[0].uses[0].source, "you");
  assert.ok(!approvals[0].uses[0].masked.includes("Real-Pa"));
  // Grants are bound to the right action types.
  assert.deepEqual(page.sent.filter((m) => m.cmd === "grant").map((m) => m.actionType), ["type", "click"]);
  // Across every step, the AI view never contained a real value.
  assert.ok(aiViews.length >= 3);
  for (const view of aiViews) {
    for (const real of Object.values(REAL)) assert.ok(!containsSecret(view, real), `${real} leaked`);
  }
});

test("denying the password approval leaves the field empty", async () => {
  const page = signInPage();
  const result = await runAgent({
    task: "Sign in to my account", send: page.send, profile: REAL,
    ui: { event() {}, requestApproval: async () => false },
  });
  assert.equal(result.status, "blocked");
  assert.equal(page.submitted(), null);
  const typed = page.sent.filter((m) => m.cmd === "execute").map((m) => m.action.element_id);
  assert.deepEqual(typed, ["e1"]); // email filled; password and submit never executed
});

test("a missing profile value stops the run with a clear message", async () => {
  const page = signInPage();
  const result = await runAgent({
    task: "Sign in", send: page.send, profile: { email: "a@b.test" },
    agent: (r) => (r.history.length ? { type: "done", reason: "" } : { type: "type", element_id: "e2", secret_ref: "password", reason: "" }),
    ui: { event() {}, requestApproval: async () => true },
  });
  assert.equal(result.status, "blocked");
  assert.match(result.message, /no password/);
});
