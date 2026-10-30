// Session state for the side panel. Holds display-safe data only: masked
// values, synthetic values and metadata. Real secrets never enter the store.

import { DEFAULT_SETTINGS, STAGES } from "../core/orchestrator.js";

export const DEFAULT_UI_SETTINGS = Object.freeze({
  ...DEFAULT_SETTINGS,
  overlay: false,
  mode: "mock",
  model: "gemini-2.5-flash",
  theme: "dark",
  testlabBaseUrl: "http://127.0.0.1:8000",
  blockedSites: [],
  useSyntheticIdentity: true,
  maxSteps: 12, // a sign-up form is ~5 fields + submit + done
  videoShield: false,
});

const idleStages = () => Object.fromEntries(STAGES.map((s) => [s, { state: "idle", detail: "" }]));

export function createStore() {
  const listeners = new Set();
  const state = {
    view: "overview",
    settings: { ...DEFAULT_UI_SETTINGS },
    apiKeySet: false,
    // Display-safe profile summary: masked own values, fake synthetic identity.
    profile: { own: {}, synthetic: {} },
    shield: { on: false, media: 0, details: 0, frames: 0, error: null },
    gemini: null, // {ok, message, at}
    tab: { id: null, url: "", origin: "", host: "", access: false, web: false, monitoring: null },
    scan: null, // scanSummary + {at, source}
    riskHistory: [],
    agent: { running: false, stages: idleStages(), actions: [], status: { text: "Idle.", tone: "" }, task: "" },
    stats: { inspected: 0, blocked: 0, honeytokenChecks: 0, honeytokenPassed: 0 },
    approvals: { pending: null, history: [] },
    selfTest: null,
    activity: [],
    ledger: { entries: [], verification: null },
    testlab: { running: null, results: {} },
  };

  return {
    state,
    set(patch) {
      Object.assign(state, typeof patch === "function" ? patch(state) : patch);
      for (const fn of listeners) fn(state);
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    resetStages() {
      state.agent = { ...state.agent, stages: idleStages(), actions: [] };
    },
  };
}
