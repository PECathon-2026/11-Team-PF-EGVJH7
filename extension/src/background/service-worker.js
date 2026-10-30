// Wires the toolbar button to the side panel and mirrors the firewall state
// on the toolbar icon. All privacy logic runs in the side panel page, which
// stays alive while open.

async function showFirewallBadge() {
  const { settings = {} } = await chrome.storage.local.get("settings");
  const on = settings.firewallEnabled !== false;
  await chrome.action.setBadgeText({ text: on ? "" : "OFF" });
  await chrome.action.setBadgeBackgroundColor({ color: "#ff5c6a" });
  await chrome.action.setTitle({ title: on ? "PrivacyLens: firewall active" : "PrivacyLens: firewall OFF, nothing is sent to the AI" });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  showFirewallBadge();
});
chrome.runtime.onStartup.addListener(showFirewallBadge);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.settings) showFirewallBadge();
});
