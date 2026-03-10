"use strict";
(() => {
  // src/disguise.ts
  var VEIL_TAG = "VEIL:";
  var PREFIX = "\u200B\u200C\u200D\uFEFF";
  var SUFFIX = "\uFEFF\u200D\u200C\u200B";
  var HANDSHAKE_PREFIX = "\u200C\u200B\u200D\uFEFF";
  var HANDSHAKE_SUFFIX = "\uFEFF\u200D\u200B\u200C";
  var VERIFY_PREFIX = "\u200D\u200C\u200B\uFEFF";
  var VERIFY_SUFFIX = "\uFEFF\u200B\u200C\u200D";
  function wrapMessage(base64Ciphertext) {
    return VEIL_TAG + PREFIX + base64Ciphertext + SUFFIX;
  }
  function unwrapMessage(text) {
    const prefixIdx = text.indexOf(PREFIX);
    if (prefixIdx !== -1) {
      const suffixIdx = text.indexOf(SUFFIX, prefixIdx + PREFIX.length);
      if (suffixIdx !== -1) return text.slice(prefixIdx + PREFIX.length, suffixIdx);
    }
    const tagIdx = text.indexOf(VEIL_TAG);
    if (tagIdx !== -1) {
      const after = text.slice(tagIdx + VEIL_TAG.length).replace(/[\u200B\u200C\u200D\uFEFF]/g, "").trim();
      if (after.length > 10) return after;
    }
    return null;
  }
  function isVeilMessage(text) {
    return text.includes(PREFIX) && text.includes(SUFFIX) || text.includes(VEIL_TAG);
  }
  function wrapHandshake(publicKeyBase64, signatureBase64) {
    return VEIL_TAG + HANDSHAKE_PREFIX + publicKeyBase64 + "." + signatureBase64 + HANDSHAKE_SUFFIX;
  }
  function unwrapHandshake(text) {
    const prefixIdx = text.indexOf(HANDSHAKE_PREFIX);
    if (prefixIdx !== -1) {
      const suffixIdx = text.indexOf(HANDSHAKE_SUFFIX, prefixIdx + HANDSHAKE_PREFIX.length);
      if (suffixIdx !== -1) {
        const payload = text.slice(prefixIdx + HANDSHAKE_PREFIX.length, suffixIdx);
        const dotIdx = payload.indexOf(".");
        if (dotIdx !== -1) {
          return { publicKey: payload.slice(0, dotIdx), signature: payload.slice(dotIdx + 1) };
        }
      }
    }
    const tagIdx = text.indexOf(VEIL_TAG);
    if (tagIdx !== -1) {
      const after = text.slice(tagIdx + VEIL_TAG.length).replace(/[\u200B\u200C\u200D\uFEFF]/g, "").trim();
      const dotIdx = after.indexOf(".");
      if (dotIdx > 0 && dotIdx < after.length - 1) {
        return { publicKey: after.slice(0, dotIdx), signature: after.slice(dotIdx + 1) };
      }
    }
    return null;
  }
  function isHandshake(text) {
    return text.includes(HANDSHAKE_PREFIX) && text.includes(HANDSHAKE_SUFFIX) || text.includes(VEIL_TAG);
  }
  function wrapVerify(encryptedFingerprint) {
    return VEIL_TAG + VERIFY_PREFIX + encryptedFingerprint + VERIFY_SUFFIX;
  }
  function unwrapVerify(text) {
    const prefixIdx = text.indexOf(VERIFY_PREFIX);
    if (prefixIdx === -1) return null;
    const suffixIdx = text.indexOf(VERIFY_SUFFIX, prefixIdx + VERIFY_PREFIX.length);
    if (suffixIdx === -1) return null;
    return text.slice(prefixIdx + VERIFY_PREFIX.length, suffixIdx);
  }
  function isVerifyMessage(text) {
    return text.includes(VERIFY_PREFIX) && text.includes(VERIFY_SUFFIX);
  }
  var VeilDisguise = {
    wrapMessage,
    unwrapMessage,
    isVeilMessage,
    wrapHandshake,
    unwrapHandshake,
    isHandshake,
    wrapVerify,
    unwrapVerify,
    isVerifyMessage,
    VEIL_TAG,
    PREFIX,
    SUFFIX
  };

  // src/content.ts
  (() => {
    let sidebarVisible = false;
    let sidebarFrame = null;
    let sidebarContainer = null;
    let pushStyleEl = null;
    let focusedInput = null;
    let onboardingMode = null;
    let scanInterval = null;
    const seenMessages = /* @__PURE__ */ new Set();
    const SIDEBAR_WIDTH = 360;
    function createSidebar() {
      if (sidebarContainer) return;
      pushStyleEl = document.createElement("style");
      pushStyleEl.id = "veil-push-style";
      (document.head || document.documentElement).appendChild(pushStyleEl);
      sidebarContainer = document.createElement("div");
      sidebarContainer.id = "veil-sidebar-container";
      sidebarFrame = document.createElement("iframe");
      sidebarFrame.src = chrome.runtime.getURL("sidebar.html");
      sidebarFrame.allow = "clipboard-write";
      sidebarFrame.id = "veil-sidebar-iframe";
      sidebarContainer.appendChild(sidebarFrame);
      document.documentElement.appendChild(sidebarContainer);
      applyLayout(true);
      sidebarVisible = true;
      startScanning();
    }
    function applyLayout(open) {
      if (!pushStyleEl) return;
      if (open) {
        pushStyleEl.textContent = `
        html.veil-sidebar-open body {
          transform: translateX(0) !important;
          width: calc(100vw - ${SIDEBAR_WIDTH}px) !important;
          max-width: calc(100vw - ${SIDEBAR_WIDTH}px) !important;
          overflow-y: auto !important;
          overflow-x: hidden !important;
          height: 100vh !important;
          position: relative !important;
        }
        html.veil-sidebar-open {
          overflow: hidden !important;
        }
        #veil-sidebar-container {
          position: fixed !important;
          top: 0 !important;
          right: 0 !important;
          width: ${SIDEBAR_WIDTH}px !important;
          height: 100vh !important;
          z-index: 2147483647 !important;
          display: block !important;
          box-shadow: -2px 0 12px rgba(0,0,0,0.3) !important;
        }
        #veil-sidebar-iframe {
          width: 100% !important;
          height: 100% !important;
          border: none !important;
          background: #0a0a0f !important;
          display: block !important;
        }
        html:not(.veil-sidebar-open) #veil-sidebar-container {
          display: none !important;
        }
      `;
        document.documentElement.classList.add("veil-sidebar-open");
      } else {
        document.documentElement.classList.remove("veil-sidebar-open");
      }
    }
    function toggleSidebar() {
      if (!sidebarContainer) {
        createSidebar();
        return;
      }
      if (sidebarVisible) {
        applyLayout(false);
        sidebarVisible = false;
        stopScanning();
      } else {
        applyLayout(true);
        sidebarVisible = true;
        startScanning();
      }
    }
    document.addEventListener(
      "focusin",
      (e) => {
        const el = e.target;
        if (el.tagName === "TEXTAREA" || el.tagName === "INPUT" || el.getAttribute("contenteditable") === "true" || el.getAttribute("contenteditable") === "") {
          focusedInput = el;
        }
      },
      true
    );
    function startOnboarding(phase) {
      onboardingMode = phase;
      document.addEventListener("click", onboardingClickHandler, true);
    }
    function stopOnboarding() {
      onboardingMode = null;
      document.removeEventListener("click", onboardingClickHandler, true);
    }
    function onboardingClickHandler(e) {
      if (sidebarContainer && sidebarContainer.contains(e.target)) return;
      e.preventDefault();
      e.stopPropagation();
      const el = e.target;
      const selector = generateSelector(el);
      if (onboardingMode === "input") {
        const hostname = window.location.hostname;
        chrome.storage.local.set({ [`veil_input_selector_${hostname}`]: selector }, () => {
          sendToSidebar({ type: "ONBOARDING_INPUT_SAVED", selector });
        });
      } else if (onboardingMode === "send") {
        const hostname = window.location.hostname;
        chrome.storage.local.set({ [`veil_send_selector_${hostname}`]: selector }, () => {
          sendToSidebar({ type: "ONBOARDING_SEND_SAVED", selector });
        });
      }
      stopOnboarding();
    }
    function generateSelector(el) {
      if (el.id) return "#" + CSS.escape(el.id);
      const path = [];
      let current = el;
      while (current && current !== document.body) {
        let seg = current.tagName.toLowerCase();
        if (current.id) {
          seg = "#" + CSS.escape(current.id);
          path.unshift(seg);
          break;
        }
        if (current.className && typeof current.className === "string") {
          const classes = current.className.trim().split(/\s+/).slice(0, 2);
          if (classes.length > 0 && classes[0]) {
            seg += "." + classes.map((c) => CSS.escape(c)).join(".");
          }
        }
        const parent = current.parentElement;
        if (parent) {
          const siblings = Array.from(parent.children).filter(
            (c) => c.tagName === current.tagName
          );
          if (siblings.length > 1) {
            const idx = siblings.indexOf(current) + 1;
            seg += `:nth-of-type(${idx})`;
          }
        }
        path.unshift(seg);
        current = current.parentElement;
      }
      return path.join(" > ");
    }
    async function injectAndSend(text) {
      const hostname = window.location.hostname;
      const data = await chrome.storage.local.get([
        `veil_input_selector_${hostname}`,
        `veil_send_selector_${hostname}`
      ]);
      const inputSelector = data[`veil_input_selector_${hostname}`];
      const sendSelector = data[`veil_send_selector_${hostname}`];
      let inputEl = inputSelector ? document.querySelector(inputSelector) : null;
      if (!inputEl) inputEl = focusedInput;
      if (!inputEl) {
        sendToSidebar({ type: "INJECT_FAILED", text });
        return;
      }
      if (inputEl.getAttribute("contenteditable") !== null) {
        inputEl.focus();
        inputEl.innerHTML = "";
        inputEl.textContent = text;
        inputEl.dispatchEvent(new Event("input", { bubbles: true }));
        inputEl.dispatchEvent(new Event("change", { bubbles: true }));
      } else {
        inputEl.focus();
        inputEl.value = text;
        inputEl.dispatchEvent(new Event("input", { bubbles: true }));
        inputEl.dispatchEvent(new Event("change", { bubbles: true }));
      }
      await new Promise((r) => setTimeout(r, 100));
      if (sendSelector) {
        const sendBtn = document.querySelector(sendSelector);
        if (sendBtn) {
          sendBtn.click();
          sendToSidebar({ type: "INJECT_SUCCESS" });
          return;
        }
      }
      inputEl.dispatchEvent(
        new KeyboardEvent("keydown", {
          key: "Enter",
          code: "Enter",
          keyCode: 13,
          which: 13,
          bubbles: true
        })
      );
      sendToSidebar({ type: "INJECT_SUCCESS" });
    }
    function startScanning() {
      if (scanInterval) return;
      scanMessages();
      scanInterval = setInterval(scanMessages, 2e3);
    }
    function stopScanning() {
      if (scanInterval) {
        clearInterval(scanInterval);
        scanInterval = null;
      }
    }
    function scanMessages() {
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
      const found = [];
      let node;
      while (node = walker.nextNode()) {
        const text = node.textContent;
        if (!text || text.length < 10) continue;
        if (sidebarContainer && sidebarContainer.contains(node)) continue;
        if (VeilDisguise.isVeilMessage(text)) {
          const payload = VeilDisguise.unwrapMessage(text);
          if (payload && !seenMessages.has(payload)) {
            seenMessages.add(payload);
            found.push({ type: "encrypted", payload });
          }
        } else if (VeilDisguise.isHandshake(text)) {
          const data = VeilDisguise.unwrapHandshake(text);
          if (data && !seenMessages.has(data.publicKey)) {
            seenMessages.add(data.publicKey);
            found.push({ type: "handshake", ...data });
          }
        } else if (VeilDisguise.isVerifyMessage(text)) {
          const payload = VeilDisguise.unwrapVerify(text);
          if (payload && !seenMessages.has(payload)) {
            seenMessages.add(payload);
            found.push({ type: "verify", payload });
          }
        }
      }
      if (found.length > 0) {
        sendToSidebar({ type: "SCANNED_MESSAGES", messages: found });
      }
    }
    function sendToSidebar(msg) {
      if (sidebarFrame && sidebarFrame.contentWindow) {
        sidebarFrame.contentWindow.postMessage({ source: "veil-content", ...msg }, "*");
      }
    }
    window.addEventListener("message", (e) => {
      if (!e.data || e.data.source !== "veil-sidebar") return;
      const msg = e.data;
      switch (msg.type) {
        case "INJECT_TEXT":
          if (msg.text) injectAndSend(msg.text);
          break;
        case "START_ONBOARDING_INPUT":
          startOnboarding("input");
          break;
        case "START_ONBOARDING_SEND":
          startOnboarding("send");
          break;
        case "SCAN_NOW":
          scanMessages();
          break;
      }
    });
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message.type === "TOGGLE_SIDEBAR") {
        toggleSidebar();
        sendResponse({ ok: true });
      }
    });
  })();
})();
