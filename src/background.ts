// Veil — Background service worker
// Routes messages between sidebar and content scripts, holds no persistent state

chrome.action.onClicked.addListener((tab) => {
  if (tab.id !== undefined) {
    chrome.tabs.sendMessage(tab.id, { type: 'TOGGLE_SIDEBAR' });
  }
});

// Route messages between sidebar (iframe) and content script
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.target === 'content') {
    // Forward from sidebar to content script in active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].id !== undefined) {
        chrome.tabs.sendMessage(tabs[0].id, message, (response) => {
          sendResponse(response);
        });
      }
    });
    return true; // async response
  }

  if (message.target === 'sidebar') {
    // Forward from content script to sidebar — sidebar listens via runtime.onMessage
    // The sidebar iframe receives this directly since it shares the extension context
    // No explicit forwarding needed — both listen on chrome.runtime.onMessage
    sendResponse({ ok: true });
  }

  if (message.type === 'GET_TAB_HOSTNAME') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].url) {
        try {
          const url = new URL(tabs[0].url);
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
