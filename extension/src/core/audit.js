// Tamper-evident privacy ledger: every entry is SHA-256 hash-chained to the
// previous one, so editing or deleting any past entry breaks verify().
// Entries hold metadata only; a final egress check rejects any entry that
// would contain a protected value.

import { validateOutgoing } from "./egress.js";

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const GENESIS = "0".repeat(64);

function canonical(entry) {
  const { seq, ts, event, detail, prev } = entry;
  return JSON.stringify({ seq, ts, event, detail, prev });
}

export class AuditLedger {
  entries = [];

  async append(event, detail = {}, inventory = []) {
    if (inventory.length && !validateOutgoing(detail, inventory).ok) {
      detail = { withheld: "Entry detail withheld: it referenced a protected value." };
    }
    const prev = this.entries.at(-1)?.hash ?? GENESIS;
    const entry = { seq: this.entries.length, ts: new Date().toISOString(), event, detail, prev };
    entry.hash = await sha256Hex(canonical(entry));
    this.entries.push(entry);
    return entry;
  }

  async verify() {
    let prev = GENESIS;
    for (const [i, entry] of this.entries.entries()) {
      if (entry.seq !== i || entry.prev !== prev) return { ok: false, brokenAt: i };
      if ((await sha256Hex(canonical(entry))) !== entry.hash) return { ok: false, brokenAt: i };
      prev = entry.hash;
    }
    return { ok: true, brokenAt: null, head: prev };
  }

  async receipt() {
    return {
      kind: "privacylens-privacy-receipt",
      generated: new Date().toISOString(),
      verification: await this.verify(),
      entries: this.entries,
    };
  }
}
