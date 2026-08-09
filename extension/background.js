// Brave Vault Injector — background service worker.
//
// Bridges the native-messaging host (brave-vault-injector) to the page. On a
// `fill` job it finds or opens a tab whose origin matches the credential's
// origin, asks that tab's content script to fill the form, and reports the
// result back to the host. The credential is held only for the dispatch and is
// never persisted or logged.

const HOST_NAME = "com.brave.vault.injector";

let port = null;

function connect() {
  port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener(onHostMessage);
  port.onDisconnect.addListener(() => {
    port = null;
    // Reconnect with a short backoff; the host exits when idle/locked.
    setTimeout(connect, 2000);
  });
}

async function onHostMessage(msg) {
  if (!msg || msg.type !== "fill") return;
  const { job_id, origin, url } = msg;
  try {
    const tabId = await findOrOpenTab(origin, url);
    // Only pass the origin + credential to the content script (not the full
    // URL); the content script re-checks its own location.origin as a guard.
    const result = await sendFill(tabId, {
      type: "fill",
      job_id,
      origin,
      username: msg.username,
      password: msg.password,
    });
    reply(job_id, !!result.ok, result.detail || "");
  } catch (e) {
    reply(job_id, false, String(e && e.message ? e.message : e));
  }
}

function reply(job_id, ok, detail) {
  if (port) port.postMessage({ type: "fill_result", job_id, ok, detail });
}

// Find an existing tab on the target origin, or open one and wait for it to
// finish loading.
async function findOrOpenTab(origin, url) {
  const tabs = await chrome.tabs.query({});
  for (const t of tabs) {
    if (t.url && originOf(t.url) === origin) return t.id;
  }
  const created = await chrome.tabs.create({ url: url || origin });
  return await waitForComplete(created.id);
}

function waitForComplete(tabId) {
  return new Promise((resolve) => {
    function listener(id, info) {
      if (id === tabId && info.status === "complete") {
        chrome.tabs.onUpdated.removeListener(listener);
        resolve(tabId);
      }
    }
    chrome.tabs.onUpdated.addListener(listener);
  });
}

function sendFill(tabId, payload) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, payload, (resp) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, detail: chrome.runtime.lastError.message });
      } else {
        resolve(resp || { ok: false, detail: "no response from content script" });
      }
    });
  });
}

function originOf(u) {
  try {
    return new URL(u).origin;
  } catch {
    return "";
  }
}

connect();
