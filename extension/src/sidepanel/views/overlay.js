import { h, icon, chip, card, setChildren, toggle } from "../ui.js";

export function overlayView(store, ctl) {
  const status = h("div");
  const controls = h("div");

  const root = h("div", { class: "view" },
    card("AI-Eye · live page overlay",
      h("p", { class: "muted small", text: "Draws boxes directly on the web page, through the extension's content script, showing which fields the AI receives in protected form and which text was quarantined. The overlay itself contains labels only, never values." }),
      controls, status),
    card("Legend",
      h("div", { class: "legend" },
        h("div", { class: "legend-row" }, h("span", { class: "swatch protected" }), h("span", { class: "mono small", text: "PROTECTED · CARD" }), h("span", { class: "muted small", text: "AI sees a synthetic value or placeholder" })),
        h("div", { class: "legend-row" }, h("span", { class: "swatch quarantined" }), h("span", { class: "mono small", text: "QUARANTINED" }), h("span", { class: "muted small", text: "Instruction-like text the AI never sees" })),
        h("div", { class: "legend-row" }, h("span", { class: "swatch censored" }), h("span", { class: "mono small", text: "CENSORED · VIDEO" }), h("span", { class: "muted small", text: "Feed blurred by the video privacy shield" })))),
    card("How it works",
      h("ol", { class: "steps small" },
        h("li", { text: "Scan the page (or run a task): every protected field gets a box." }),
        h("li", { text: "The boxes follow the real page layout; resize or scroll the page normally." }),
        h("li", { text: "Turning the overlay off removes it from the page immediately." }))),
  );

  function update(S) {
    const mon = S.tab.monitoring;
    setChildren(controls,
      toggle({ id: "overlay-toggle", checked: S.settings.overlay, label: "Show AI-Eye overlay on the page", hint: S.tab.access ? null : "Grant access to this site first",
        onChange: (v) => ctl.updateSettings({ overlay: v }) }),
      toggle({ id: "video-shield-toggle", checked: S.settings.videoShield, label: "Video privacy shield",
        hint: "Blurs video and camera feeds and every detected personal detail (names, emails, phones, cards…) on the page: for screen sharing, recordings and shoulder-surfing.",
        onChange: (v) => ctl.updateSettings({ videoShield: v }) }),
      h("button", { class: "btn btn-block", onclick: () => ctl.scanCurrentPage() }, icon("scan"), "Rescan and redraw"));
    setChildren(status,
      h("div", { class: "monitor" },
        h("span", { class: `dot ${mon ? "dot-live" : ""}`, id: "monitor-dot" }),
        h("span", { id: "monitor-text", text: mon ? "Page monitoring active" : "Not attached to this page" }),
        mon ? chip(mon.overlayVisible ? "Overlay visible" : "Overlay hidden", mon.overlayVisible ? "ok" : "neutral") : null),
      mon ? h("div", { class: "muted small", text: `${mon.protectedCount} protected box(es), ${mon.quarantinedCount} quarantined on the page.` }) : null,
      mon?.videoShield ? h("div", { class: "monitor", id: "shield-status" },
        icon("eye"),
        h("span", { text: `Shield on: ${mon.censoredMedia} video feed(s) and ${mon.censoredDetails} personal detail(s) blurred` })) : null,
      h("p", { class: "muted tiny", text: "The AI never receives video frames or screenshots: PrivacyLens sends text only. The shield blurs whole frames; it does not detect individual faces." }));
  }

  return { root, update };
}
