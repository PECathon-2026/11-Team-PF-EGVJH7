import { test } from "node:test";
import assert from "node:assert/strict";

import { detect } from "../src/core/detect.js";
import { containsSecret } from "../src/core/egress.js";
import { findLabelledNames, isNameField } from "../src/core/names.js";
import { scanPage } from "../src/core/orchestrator.js";
import { SCENARIOS, evaluateScan, verdictOf } from "../src/core/scenarios.js";

const el = (id, props) => ({ id, tag: "p", type: null, name: null, label: "", placeholder: "", text: "", value: "", attrs: {}, visible: true, domId: "", ...props });

test("labelled names are found with exact spans; non-names are not", () => {
  const names = (t) => findLabelledNames(t).map(([s, e]) => t.slice(s, e));
  assert.deepEqual(names("Name: Alice Smith"), ["Alice Smith"]);
  assert.deepEqual(names("Host: Rahul Mehta (you) · Speaker - Diya K"), ["Rahul Mehta", "Diya K"]);
  assert.deepEqual(names("From: Priya Sharma <p@x.test>"), ["Priya Sharma"]);
  assert.deepEqual(names("Name: Required"), []);
  assert.deepEqual(names("Rename: Fix Bug"), []);         // "name" inside another word
  assert.deepEqual(names("the host is ready"), []);       // no label separator
  assert.deepEqual(names("Name: alice"), []);             // not capitalised: not treated as a name
});

test("name fields are recognised, look-alikes are not", () => {
  for (const hay of ["full name", "name", "first name", "name on card", "card holder", "display name"]) assert.ok(isNameField(hay), hay);
  for (const hay of ["username", "file name", "company name", "host name", "product name"]) assert.ok(!isNameField(hay), hay);
});

test("a name-on-card field is a PERSON, not a CARD", () => {
  const dets = detect({ elements: [el("e1", { tag: "input", type: "text", label: "Name on card", value: "PRIYA SHARMA" })] });
  assert.deepEqual(dets.map((d) => d.type), ["PERSON"]);
});

const videoPage = () => ({
  url: "http://127.0.0.1:8000/video.html", title: "Video Call", snapshotId: "v1",
  elements: [
    el("t1", { tag: "h1", text: "Video Conference" }),
    el("t2", { text: "Name: Alice Smith" }),
    el("t3", { text: "Email: alice.smith@example.com" }),
  ],
});

test("video call: names and emails are replaced for the AI", () => {
  const scan = scanPage(videoPage(), { task: "Who is in this call?" });
  assert.ok(!containsSecret(scan.request, "Alice Smith"));
  assert.ok(!containsSecret(scan.request, "alice.smith@example.com"));
  const line = scan.request.elements.find((e) => e.id === "t2").text;
  assert.match(line, /^Name: [A-Z][a-z]+ [A-Z][a-z]+$/); // still reads as a name, so the AI keeps context
  assert.equal(scan.egress.ok, true);
});

test("video scenario: name check now passes; only per-face detection is unsupported", () => {
  const scenario = SCENARIOS.find((s) => s.id === "video");
  const snapshot = videoPage();
  const checks = evaluateScan(scenario, snapshot, scanPage(snapshot, { task: scenario.task }));
  assert.deepEqual(checks.filter((c) => c.status !== "pass").map((c) => c.name), ["Per-face detection and redaction"]);
  assert.equal(verdictOf(checks), "partial");
});
