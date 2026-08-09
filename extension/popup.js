// Popup: grant the extension host permission for a set of hosts. The click here
// IS the user gesture that chrome.permissions.request requires — which is why
// the grab flow can't request it on its own.

function patternsFrom(input) {
  return input
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((h) => `*://${h}/*`);
}

const status = document.getElementById("status");

document.getElementById("grant").addEventListener("click", async () => {
  const patterns = patternsFrom(document.getElementById("hosts").value);
  if (!patterns.length) {
    status.textContent = "Enter at least one host.";
    return;
  }
  try {
    const granted = await chrome.permissions.request({ origins: patterns });
    status.textContent = granted
      ? "Granted. You can close this and retry the grab."
      : "Declined.";
  } catch (e) {
    status.textContent = "Error: " + (e && e.message ? e.message : e);
  }
});

document.getElementById("check").addEventListener("click", async () => {
  const patterns = patternsFrom(document.getElementById("hosts").value);
  const has = await chrome.permissions.contains({ origins: patterns });
  status.textContent = has ? "Already granted." : "Not granted yet.";
});
