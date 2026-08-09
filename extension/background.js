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
  // Guard: never open a second port. A double-connect spawns a duplicate native
  // host, and the broker may then wake the stale one — causing grabs to hang.
  if (port) return;
  port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener(onHostMessage);
  port.onDisconnect.addListener(() => {
    port = null;
    // Reconnect with a short backoff; the host exits when idle/locked.
    setTimeout(connect, 2000);
  });
}

// MV3 suspends idle service workers. An open native-messaging port keeps the
// worker alive, but the worker can still be torn down and restarted — so
// (re)connect on every wake event, and the `if (port) return` guard makes this
// idempotent.
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);

async function onHostMessage(msg) {
  if (!msg) return;
  if (msg.type === "fill") return onFill(msg);
  if (msg.type === "grab_session") return onGrabSession(msg);
}

async function onFill(msg) {
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

// Grab session cookies for the approved hosts. The security guarantee is the
// browser's, not ours: the extension holds NO standing host access, so it must
// obtain optional_host_permissions for exactly these hosts. Brave prompts the
// user and refuses every other origin (e.g. a bank) at the sandbox level.
async function onGrabSession(msg) {
  const { job_id, origins } = msg;
  try {
    const patterns = (origins || []).map((h) => `*://${h}/*`);
    if (!patterns.length) {
      return replySession(job_id, false, [], "no origins requested");
    }
    // chrome.permissions.request() needs a user gesture, which we don't have
    // when reacting to a native message — so first check if permission is
    // already held (no gesture needed). If not, try to request, but never hang:
    // if the request can't run without a gesture, tell the user to grant it once.
    let has = await chrome.permissions.contains({ origins: patterns });
    if (!has) {
      try {
        has = await chrome.permissions.request({ origins: patterns });
      } catch (e) {
        return replySession(
          job_id,
          false,
          [],
          "host permission not granted — open the extension and allow access to " +
            origins.join(", ") +
            " once (needs a click), then retry"
        );
      }
      if (!has) {
        return replySession(job_id, false, [], "user declined host permission");
      }
    }
    const seen = new Set();
    const out = [];
    for (const host of origins) {
      // getAll by domain returns cookies for that host (and its dot-domain
      // parents that set domain cookies), but only for hosts we now have
      // permission to read.
      const cookies = await chrome.cookies.getAll({ domain: host });
      for (const c of cookies) {
        const key = `${c.domain}|${c.path}|${c.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({
          name: c.name,
          value: c.value,
          domain: c.domain,
          path: c.path,
          secure: !!c.secure,
          http_only: !!c.httpOnly,
          same_site: sameSite(c.sameSite),
          expiration: c.expirationDate || 0,
        });
      }
    }
    replySession(job_id, true, out, "");
  } catch (e) {
    replySession(job_id, false, [], String(e && e.message ? e.message : e));
  }
}

function sameSite(s) {
  switch (s) {
    case "strict":
      return "Strict";
    case "lax":
      return "Lax";
    case "no_restriction":
      return "None";
    default:
      return "";
  }
}

function reply(job_id, ok, detail) {
  if (port) port.postMessage({ type: "fill_result", job_id, ok, detail });
}

function replySession(job_id, ok, cookies, detail) {
  if (port) port.postMessage({ type: "session_result", job_id, ok, cookies, detail });
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
