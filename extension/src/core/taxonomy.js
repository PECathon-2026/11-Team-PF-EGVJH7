// Display metadata for detection types: labels, severities and how each one
// is found. Pure data; no detection logic lives here.

export const CATEGORIES = [
  { id: "AADHAAR", label: "Aadhaar", severity: "critical", supported: true },
  { id: "PAN", label: "PAN", severity: "critical", supported: true },
  { id: "CARD", label: "Credit/debit cards", severity: "critical", supported: true },
  { id: "PASSWORD", label: "Passwords", severity: "critical", supported: true },
  { id: "OTP", label: "OTPs", severity: "high", supported: true },
  { id: "API_KEY", label: "API keys", severity: "critical", supported: true },
  { id: "TOKEN", label: "Authentication tokens", severity: "critical", supported: true },
  { id: "EMAIL", label: "Email addresses", severity: "medium", supported: true },
  { id: "PHONE", label: "Phone numbers", severity: "medium", supported: true },
  { id: "IP", label: "IP addresses", severity: "low", supported: true },
  {
    id: "PERSON", label: "Personal names", severity: "medium", supported: true,
    note: "From labels (Name:, Host:, Speaker:) and name fields; unlabelled names in free text are not detected.",
  },
  {
    id: "OTHER", label: "Other contextual PII", severity: "medium", supported: true,
    note: "Postal addresses, from field labels.",
  },
];

export const SEVERITY_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

/** Category for display. `real` never leaves this function. */
export function categoryOf(type, real = "") {
  if (type === "API_KEY" && /^(eyJ|ghp_)/.test(real)) return "TOKEN";
  if (type === "CREDENTIAL" || type === "SECRET") return "PASSWORD";
  if (type === "PERSON") return "PERSON";
  if (["ADDRESS", "OTHER"].includes(type)) return "OTHER";
  return CATEGORIES.some((c) => c.id === type) ? type : "OTHER";
}

export function severityOf(category) {
  return CATEGORIES.find((c) => c.id === category)?.severity ?? "medium";
}

export function labelOf(category) {
  return CATEGORIES.find((c) => c.id === category)?.label ?? category;
}

/** Human-readable detection method for a P2 detection. */
export function methodOf(detection) {
  if (detection.source === "dom") return "Page structure (field type, autocomplete, label)";
  if (detection.type === "CARD") return "Pattern + Luhn checksum";
  if (detection.type === "AADHAAR") return "Pattern + Verhoeff checksum";
  if (detection.type === "OTP") return "Pattern + OTP context words";
  return "Pattern match";
}
