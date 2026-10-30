// Reads {"texts": [...], "risk": [[{type, confidence}, ...], ...]} on stdin and
// prints each finder's spans plus mosaicRisk() results as JSON. Used by
// tests/test_extension_parity.py to compare against the Python P2.
import { mosaicRisk } from "../src/core/detect.js";
import { FINDERS } from "../src/core/patterns.js";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const { texts, risk = [] } = JSON.parse(input);
const spans = texts.map((text) =>
  Object.fromEntries(FINDERS.map(([type, fn]) => [type, fn(text).map(([s, e]) => [s, e])])),
);
process.stdout.write(JSON.stringify({ spans, risk: risk.map((dets) => mosaicRisk(dets)) }));
