import { h, icon, chip, card, empty, setChildren } from "../ui.js";

// A short, human result for an entry, derived from its metadata.
function resultOf(e) {
  const d = e.detail || {};
  if ("approved" in d) return [d.approved ? "approved" : "denied", d.approved ? "warn" : "ok"];
  if ("ok" in d) return [d.ok ? "ok" : "failed", d.ok ? "ok" : "bad"];
  if ("egressOk" in d) return [d.egressOk ? "clean" : "blocked", d.egressOk ? "ok" : "bad"];
  if ("verdict" in d) return [d.verdict, d.verdict === "pass" ? "ok" : d.verdict === "partial" ? "warn" : "bad"];
  if ("status" in d) return [d.status, d.status === "completed" ? "ok" : "warn"];
  if ("granted" in d) return [d.granted ? "granted" : "refused", "neutral"];
  return ["recorded", "neutral"];
}

export function ledgerView(store, ctl) {
  const typeFilter = h("select", { id: "ledger-type", "aria-label": "Filter by event type" });
  const from = h("input", { type: "date", id: "ledger-from", "aria-label": "From date" });
  const to = h("input", { type: "date", id: "ledger-to", "aria-label": "To date" });
  const status = h("div", { id: "ledger-status" });
  const list = h("ol", { class: "ledger", id: "ledger" });

  let last;
  const rerender = () => {
    last = null;
    update(store.state);
  };
  for (const f of [typeFilter, from, to]) f.addEventListener("change", rerender);

  const root = h("div", { class: "view" },
    card("Security ledger",
      h("p", { class: "muted small", text: "Every step is appended to a SHA-256 hash chain: each entry's hash covers its content and the previous hash, so editing or deleting any entry breaks verification. Entries hold metadata only, never your data." }),
      h("div", { class: "row gap wrap" },
        h("button", { class: "btn btn-primary", id: "verify", onclick: () => ctl.verifyLedger() }, icon("shieldCheck"), "Verify hash chain"),
        h("button", { class: "btn", id: "export", onclick: () => ctl.exportReceipt() }, icon("download"), "Export privacy receipt")),
      status),
    card("Entries",
      h("div", { class: "filters" },
        h("label", {}, h("span", { class: "muted small", text: "Event" }), typeFilter),
        h("label", {}, h("span", { class: "muted small", text: "From" }), from),
        h("label", {}, h("span", { class: "muted small", text: "To" }), to)),
      list),
  );

  function update(S) {
    const { entries, verification } = S.ledger;
    const key = `${entries.length}:${entries.at(-1)?.hash}:${verification?.at}`;
    if (key === last) return;
    last = key;

    const types = [...new Set(entries.map((e) => e.event))].sort();
    const current = typeFilter.value;
    setChildren(typeFilter, h("option", { value: "", text: "All events" }), ...types.map((t) => h("option", { value: t, text: t })));
    typeFilter.value = types.includes(current) ? current : "";

    setChildren(status, verification
      ? h("div", { class: `verdict ${verification.ok ? "ok" : "bad"}` },
          icon(verification.ok ? "shieldCheck" : "alert"),
          h("span", { text: verification.ok
            ? `Chain intact: ${entries.length} entries verified, head ${verification.head?.slice(0, 16) ?? "—"}…`
            : `Chain BROKEN at entry #${verification.brokenAt}: entries from there on are unverified.` }))
      : h("div", { class: "muted small", text: `${entries.length} entries · not yet verified in this view. Retention: this session only.` }));

    const fromTs = from.value ? new Date(`${from.value}T00:00:00`).getTime() : -Infinity;
    const toTs = to.value ? new Date(`${to.value}T23:59:59.999`).getTime() : Infinity;
    const shown = entries.filter((e) => (!typeFilter.value || e.event === typeFilter.value) && Date.parse(e.ts) >= fromTs && Date.parse(e.ts) <= toTs);

    setChildren(list, shown.length
      ? shown.slice().reverse().map((e) => {
          const verified = verification ? (verification.ok || e.seq < verification.brokenAt) : null;
          const [result, tone] = resultOf(e);
          return h("li", { class: "ledger-entry" },
            h("div", { class: "ledger-head" },
              h("span", { class: "mono small", text: `#${e.seq}` }),
              h("strong", { text: e.event }),
              chip(result, tone),
              verified == null ? chip("unverified", "neutral") : chip(verified ? "verified" : "unverified", verified ? "ok" : "bad")),
            h("div", { class: "muted small", text: new Date(e.ts).toLocaleString() }),
            h("div", { class: "mono tiny hash", text: `hash ${e.hash.slice(0, 20)}… ← prev ${e.prev.slice(0, 12)}…` }),
            Object.keys(e.detail || {}).length
              ? h("details", {}, h("summary", { class: "small", text: "Metadata" }), h("pre", { class: "payload mono", text: JSON.stringify(e.detail, null, 2) }))
              : null);
        })
      : [empty(entries.length ? "No entries match the filters." : "No entries yet.")]);
  }

  return { root, update };
}
