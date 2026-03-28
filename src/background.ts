// Veil — Background service worker
// Routes messages between popup and content script, holds no persistent state.

// Allow content scripts to access chrome.storage.session (default is extension-only)
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' });

/** Find the active tab reliably — even when called from a popup.
 *  Service workers don't have a stable "currentWindow" — query ALL active tabs
 *  and pick the most recently accessed non-extension tab. */
function getActiveTab(callback: (tab: chrome.tabs.Tab | null) => void): void {
  chrome.tabs.query({ active: true }, (tabs) => {
    // Filter to real pages, sort by lastAccessed (most recent first)
    const candidates = tabs
      .filter((t) => t.url && !t.url.startsWith('chrome-extension://') && !t.url.startsWith('chrome://'))
      .sort((a, b) => (b.lastAccessed ?? 0) - (a.lastAccessed ?? 0));
    console.log('Veil bg: getActiveTab candidates:', candidates.map((t) => ({ id: t.id, url: t.url })));
    callback(candidates[0] ?? null);
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  // Forward from popup to content script in active tab
  if (message.target === 'content') {
    getActiveTab((tab) => {
      if (tab && tab.id !== undefined) {
        chrome.tabs.sendMessage(tab.id, message, (response) => {
          sendResponse(response);
        });
      } else {
        sendResponse(null);
      }
    });
    return true; // async response
  }

  // Popup asks for the active tab's hostname
  if (message.type === 'GET_TAB_HOSTNAME') {
    getActiveTab((tab) => {
      if (tab && tab.url) {
        try {
          const url = new URL(tab.url);
          sendResponse({ hostname: url.hostname });
        } catch {
          sendResponse({ hostname: '' });
        }
      } else {
        sendResponse({ hostname: '' });
      }
    });
    return true;
  }
});
