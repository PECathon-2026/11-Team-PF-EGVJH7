import { test } from "node:test";
import assert from "node:assert/strict";

import { ACTION_SCHEMA, EgressBlockedError, geminiAgent, mockAgent } from "../src/core/agent.js";
import { runAgent } from "../src/core/orchestrator.js";
import { parseAction, validateAction } from "../src/core/policy.js";

const REAL_CARD = "4111 1111 1111 1111";

const fakeResponse = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const geminiReply = (text, extra = {}) => fakeResponse(200, { candidates: [{ content: { parts: [{ text }] }, finishReason: "STOP", ...extra }] });

// --- Gemini request/response handling (no network: fetch is injected) ------

test("Gemini request uses the action schema and sends only the sanitized request", async () => {
  let sent;
  const fetchImpl = async (url, init) => {
    sent = { url, init, body: JSON.parse(init.body) };
    return geminiReply('{"type":"done","reason":"ok"}');
  };
  const request = { task: "Pay", url: "https://shop.test/checkout", elements: [{ id: "e1", value: "4024 0071 2345 6789" }], history: [] };
  const text = await geminiAgent(request, {
    apiKey: "k", model: "gemini-2.5-flash", inventory: [REAL_CARD], allowedSynthetic: ["4024 0071 2345 6789"], fetchImpl,
  });
  assert.equal(text, '{"type":"done","reason":"ok"}');
  assert.match(sent.url, /models\/gemini-2\.5-flash:generateContent$/);
  assert.equal(sent.init.headers["x-goog-api-key"], "k");
  assert.equal(sent.init.credentials, "omit");
  assert.deepEqual(sent.body.generationConfig.responseSchema, ACTION_SCHEMA);
  assert.equal(sent.body.generationConfig.responseMimeType, "application/json");
  assert.ok(!sent.init.body.includes(REAL_CARD));
});

test("Gemini is never called when the body fails the egress check", async () => {
  let called = false;
  const fetchImpl = async () => { called = true; return geminiReply("{}"); };
  await assert.rejects(
    geminiAgent({ task: `pay with ${REAL_CARD}`, elements: [], history: [] }, { apiKey: "k", model: "m", inventory: [REAL_CARD], allowedSynthetic: [], fetchImpl }),
    EgressBlockedError,
  );
  assert.equal(called, false);
});

test("Gemini errors become readable messages", async () => {
  const run = (response) => geminiAgent({ task: "x", elements: [], history: [] }, {
    apiKey: "k", model: "m", inventory: ["secret-value"], allowedSynthetic: [], fetchImpl: async () => response,
  });
  await assert.rejects(run(fakeResponse(429, {})), /rate limit/);
  await assert.rejects(run(fakeResponse(404, {})), /model not found/);
  await assert.rejects(run(fakeResponse(403, {})), /rejected the API key/);
  await assert.rejects(run(fakeResponse(200, { promptFeedback: { blockReason: "SAFETY" } })), /refused the request \(SAFETY\)/);
  await assert.rejects(run(fakeResponse(200, { candidates: [{ content: { parts: [] }, finishReason: "SAFETY" }] })), /finish reason: SAFETY/);
});

test("model output with blank fields or a one-element array is accepted", () => {
  const view = { elements: [] };
  const blank = parseAction('{"type":"scroll","element_id":"","text":"","url":"","reason":"look"}');
  assert.deepEqual(blank, { type: "scroll", element_id: null, text: null, url: null, reason: "look" });
  assert.equal(validateAction(blank, view, new Map()).ok, true);
  assert.equal(parseAction('[{"type":"done","reason":"ok"}]').type, "done");
  assert.throws(() => parseAction('[{"type":"done"},{"type":"done"}]'));
  // Typing an empty string (clearing a field) is still a deliberate value.
  assert.equal(parseAction('{"type":"type","element_id":"e1","text":"","reason":"clear"}').text, "");
});

test("mock agent tracks clicks per page, so ids from a previous page don't block it", () => {
  const elements = [{ id: "e1", tag: "a", text: "View cart", label: "", value: "" }];
  const onOtherPage = mockAgent({ task: "Go to the cart", url: "https://s.test/b", elements, history: [{ type: "click", element_id: "e1", page: "https://s.test/a" }] });
  assert.equal(onOtherPage.type, "click");
  const samePage = mockAgent({ task: "Go to the cart", url: "https://s.test/a", elements, history: [{ type: "click", element_id: "e1", page: "https://s.test/a" }] });
  assert.equal(samePage.type, "done");
});

// --- Typing flow through the real loop ------------------------------------------

const el = (id, props) => ({ id, tag: "input", type: "text", name: null, label: "", placeholder: "", text: "", value: "", attrs: {}, visible: true, ...props });
const paymentPage = () => ({
  url: "https://shop.test/pay", title: "Pay", snapshotId: "snap-1",
  elements: [
    el("e1", { name: "card", label: "Card number", value: REAL_CARD, attrs: { autocomplete: "cc-number" } }),
    el("e2", { name: "card_confirm", label: "Confirm card number", placeholder: "Re-enter card" }),
  ],
});

// A planner that copies the (synthetic) card it was shown into the confirm field.
const copyCardAgent = (request) => {
  if (request.history.length) return { type: "done", reason: "Filled." };
  const shown = request.elements.find((e) => e.id === "e1").value;
  return { type: "type", element_id: "e2", text: shown, reason: "Confirm the card number." };
};

async function runTyping(approve) {
  const sent = [];
  const send = async (msg) => {
    sent.push(msg);
    return msg.cmd === "snapshot" ? { ok: true, snapshot: paymentPage() } : { ok: true };
  };
  let card;
  const result = await runAgent({
    task: "Confirm my card number", send, agent: copyCardAgent,
    ui: { event() {}, requestApproval: async (c) => { card = c; return approve; } },
  });
  return { sent, card, result };
}

test("typing a real card: the AI only sees a synthetic one; approval swaps in the real value", async () => {
  const { sent, card, result } = await runTyping(true);
  assert.equal(card.action, "type");
  assert.equal(card.risk.level, "critical");
  assert.equal(card.uses.length, 1);
  assert.equal(card.uses[0].type, "CARD");
  assert.ok(card.uses[0].masked.endsWith("1111") && !card.uses[0].masked.includes("4111"), card.uses[0].masked);

  const grant = sent.find((m) => m.cmd === "grant");
  const execute = sent.find((m) => m.cmd === "execute");
  assert.equal(grant.actionType, "type");
  assert.equal(grant.elementId, "e2");
  assert.equal(execute.grant, grant.nonce);
  assert.equal(execute.action.text, REAL_CARD); // real value only at execution time
  assert.equal(result.status, "completed");
});

test("typing a real card: deny sends no grant and executes nothing", async () => {
  const { sent, result } = await runTyping(false);
  assert.equal(result.status, "blocked");
  assert.ok(!sent.some((m) => m.cmd === "grant" || m.cmd === "execute"));
});

test("multi-page run: the transport is asked for a fresh snapshot on every step", async () => {
  const pages = [
    { url: "https://shop.test/catalog", title: "Catalog", snapshotId: "s1", elements: [el("e1", { tag: "a", type: null, text: "View cart" })] },
    { url: "https://shop.test/checkout", title: "Checkout", snapshotId: "s2", elements: [el("e1", { tag: "button", type: "button", text: "Pay Now" })] },
  ];
  let page = 0;
  const send = async (msg) => {
    if (msg.cmd === "snapshot") return { ok: true, snapshot: pages[page] };
    if (msg.cmd === "execute" && msg.action.type === "click" && pages[page].url.endsWith("catalog")) page = 1; // link navigates
    return { ok: true };
  };
  let card;
  const result = await runAgent({
    task: "Go to the cart and pay", send,
    ui: { event() {}, requestApproval: async (c) => { card = c; return false; } },
  });
  assert.equal(card?.target, "Pay Now", "agent reached the second page and asked about Pay");
  assert.equal(result.status, "blocked");
});
