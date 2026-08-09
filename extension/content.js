// Brave Vault Injector — content script.
//
// Fills the username/password into the page's login form on request from the
// background worker. Defense-in-depth origin binding: even though the broker
// and the background worker both check the origin, THIS script asserts its own
// `location.origin` before touching any field — so a fill can only ever land on
// the exact origin the credential belongs to. Does not auto-submit.

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "fill") return;

  // Origin guard: refuse if this document is not the intended origin.
  if (location.origin !== msg.origin) {
    sendResponse({ ok: false, detail: `origin mismatch: page is ${location.origin}` });
    return;
  }

  const pass = findPasswordField();
  if (!pass) {
    sendResponse({ ok: false, detail: "no password field found" });
    return;
  }
  const user = findUsernameField(pass);

  if (user && msg.username) setValue(user, msg.username);
  setValue(pass, msg.password);

  sendResponse({ ok: true, detail: "filled" });
  // Return true not needed — we call sendResponse synchronously.
});

// The first visible password input on the page.
function findPasswordField() {
  const candidates = Array.from(document.querySelectorAll('input[type="password"]'));
  return candidates.find(isVisible) || null;
}

// A username-ish field near (preferably before) the password field.
function findUsernameField(passEl) {
  const selectors = [
    'input[autocomplete="username"]',
    'input[type="email"]',
    'input[name="username"]',
    'input[name="email"]',
    'input[id*="user" i]',
    'input[id*="email" i]',
    'input[type="text"]',
  ];
  for (const sel of selectors) {
    const els = Array.from(document.querySelectorAll(sel)).filter(isVisible);
    if (els.length) {
      // Prefer a field that appears before the password in document order.
      const before = els.filter(
        (e) => e.compareDocumentPosition(passEl) & Node.DOCUMENT_POSITION_FOLLOWING
      );
      return (before.length ? before[before.length - 1] : els[0]);
    }
  }
  return null;
}

function isVisible(el) {
  if (!el) return false;
  const rect = el.getBoundingClientRect();
  const style = window.getComputedStyle(el);
  return (
    rect.width > 0 &&
    rect.height > 0 &&
    style.visibility !== "hidden" &&
    style.display !== "none"
  );
}

// Set a value and fire the events frameworks (React/Vue) listen for.
function setValue(el, value) {
  el.focus();
  const proto = Object.getPrototypeOf(el);
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  if (setter) setter.call(el, value);
  else el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  el.blur();
}
