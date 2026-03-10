"use strict";
(() => {
  // src/background.ts
  chrome.action.onClicked.addListener((tab) => {
    if (tab.id !== void 0) {
      chrome.tabs.sendMessage(tab.id, { type: "TOGGLE_SIDEBAR" });
    }
  });
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.target === "content") {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].id !== void 0) {
          chrome.tabs.sendMessage(tabs[0].id, message, (response) => {
            sendResponse(response);
          });
        }
      });
      return true;
    }
    if (message.target === "sidebar") {
      sendResponse({ ok: true });
    }
    if (message.type === "GET_TAB_HOSTNAME") {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].url) {
          try {
            const url = new URL(tabs[0].url);
            sendResponse({ hostname: url.hostname });
          } catch {
            sendResponse({ hostname: "" });
          }
        } else {
          sendResponse({ hostname: "" });
        }
      });
      return true;
    }
  });
})();
