// Tiny DOM helpers. All dynamic text goes through textContent; the only
// innerHTML-free SVG is built from the constant path table below.

export function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key in node && typeof value !== "string") node[key] = value;
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export const $ = (selector, root = document) => root.querySelector(selector);

const PATHS = {
  shield: ["M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"],
  shieldCheck: ["M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z", "M9 12l2 2 4-4"],
  shieldOff: ["M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z", "M4 4l16 16"],
  scan: ["M4 8V5a1 1 0 0 1 1-1h3", "M16 4h3a1 1 0 0 1 1 1v3", "M20 16v3a1 1 0 0 1-1 1h-3", "M8 20H5a1 1 0 0 1-1-1v-3", "M7 12h10"],
  eye: ["M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z", "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"],
  bot: ["M5 9h14v10H5z", "M12 5v4", "M12 3a1 1 0 1 0 0 2 1 1 0 0 0 0-2z", "M9 14h.01", "M15 14h.01", "M2 13v3", "M22 13v3"],
  hand: ["M7 11V6a1.5 1.5 0 0 1 3 0v4", "M10 10V4.5a1.5 1.5 0 0 1 3 0V10", "M13 10V5.5a1.5 1.5 0 0 1 3 0V11", "M16 11V8a1.5 1.5 0 0 1 3 0v6a7 7 0 0 1-7 7h-.5A6.5 6.5 0 0 1 6 18l-2.5-4a1.5 1.5 0 0 1 2.5-1.7L7 14"],
  alert: ["M12 3l9.5 17H2.5L12 3z", "M12 10v4", "M12 17h.01"],
  check: ["M5 12l5 5L20 7"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  list: ["M9 6h11", "M9 12h11", "M9 18h11", "M4 6h.01", "M4 12h.01", "M4 18h.01"],
  flask: ["M9 3h6", "M10 3v6L4.5 18.5A1.7 1.7 0 0 0 6 21h12a1.7 1.7 0 0 0 1.5-2.5L14 9V3", "M7 15h10"],
  settings: ["M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z", "M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"],
  gauge: ["M12 14l4-4", "M3.3 19a10 10 0 1 1 17.4 0"],
  home: ["M3 11l9-7 9 7", "M5 10v10h14V10"],
  lock: ["M6 11h12v10H6z", "M8 11V7a4 4 0 0 1 8 0v4"],
  globe: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M3 12h18", "M12 3c2.5 3 2.5 15 0 18", "M12 3c-2.5 3-2.5 15 0 18"],
  play: ["M7 4l13 8-13 8z"],
  stop: ["M6 6h12v12H6z"],
  download: ["M12 4v11", "M7 10l5 5 5-5", "M5 20h14"],
  link: ["M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1", "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"],
};

export function icon(name, size = 16) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const d of PATHS[name] || []) {
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

export const chip = (text, tone = "neutral", extra = "") => h("span", { class: `chip chip-${tone} ${extra}`.trim(), text });

export function toggle({ id, checked, label, hint, onChange, disabled }) {
  const input = h("input", { type: "checkbox", role: "switch", id, checked: Boolean(checked), disabled: Boolean(disabled) });
  input.addEventListener("change", () => onChange(input.checked));
  return h("label", { class: "switch-row", for: id },
    h("span", { class: "switch-text" }, h("span", { class: "switch-label", text: label }), hint ? h("span", { class: "muted small", text: hint }) : null),
    h("span", { class: "switch" }, input, h("span", { class: "switch-track", "aria-hidden": "true" })),
  );
}

export function card(title, ...children) {
  return h("section", { class: "card" }, title ? h("h2", { class: "card-title", text: title }) : null, ...children);
}

export const empty = (text) => h("div", { class: "empty", text });

export function time(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function setChildren(node, ...children) {
  node.replaceChildren(...children.flat().filter((c) => c != null && c !== false));
}

export const TONE_BY_SEVERITY = { critical: "bad", high: "warn", medium: "info", low: "neutral" };
