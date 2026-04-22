let bridgeActive = true;

function disableBridge() {
  if (!bridgeActive) return;
  bridgeActive = false;
  window.removeEventListener("message", onMessage);
}

function isContextInvalidatedError(err) {
  const msg = String(err?.message || err || "");
  return msg.includes("Extension context invalidated");
}

// Inject fetch interceptor via external file (CSP-safe)
try {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("interceptor.js");
  script.onload = () => script.remove();
  script.onerror = () => script.remove();
  document.documentElement.appendChild(script);
} catch (err) {
  if (isContextInvalidatedError(err)) {
    disableBridge();
  } else {
    console.warn("[ControlHub] interceptor injection failed:", String(err?.message || err));
  }
}

console.log('[ControlHub] Content script loaded on', window.location.href);

// Safe wrapper: when the extension is reloaded/updated while a Lovable tab
// is still open, the old content script keeps running but its connection to
// the service worker is severed. Any chrome.runtime.* call then throws
// "Extension context invalidated." This swallows that specific error so it
// doesn't surface as an unhandled exception in the page console.
function safeSendMessage(payload) {
  try {
    if (!chrome.runtime?.id) return; // context already gone
    chrome.runtime.sendMessage(payload, () => {
      try {
        // Touch lastError so Chrome doesn't log "Unchecked runtime.lastError".
        void chrome.runtime?.lastError;
      } catch (err) {
        if (isContextInvalidatedError(err)) {
          disableBridge();
          return;
        }
        console.warn('[ControlHub] sendMessage callback failed:', String(err?.message || err));
      }
    });
  } catch (err) {
    const msg = String(err?.message || err);
    if (msg.includes("Extension context invalidated")) {
      // Stale content script — the user needs to reload the tab. Stop
      // listening to avoid spamming the console on every postMessage.
      disableBridge();
      return;
    }
    // Anything else is genuinely unexpected — keep visibility.
    console.warn('[ControlHub] sendMessage failed:', msg);
  }
}

// Relay messages from page context to background
function onMessage(event) {
  if (!bridgeActive) return;
  if (event.source !== window) return;

  if (event.data?.type === "LOVABLE_CT_AUTH_TOKEN") {
    safeSendMessage({
      type: "LOVABLE_AUTH_TOKEN",
      token: event.data.token,
      url: event.data.url || null,
    });
    return;
  }

  if (event.data?.type === "LOVABLE_CT_INTERCEPT") {
    safeSendMessage({
      type: "LOVABLE_API_DATA",
      data: {
        url: event.data.url,
        method: event.data.method || 'GET',
        body: event.data.body,
      },
    });
  }
}
window.addEventListener("message", onMessage);
