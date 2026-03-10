// Veil — Content script
// Injected into every page: sidebar injection, DOM scanning, input detection

import { VeilCrypto } from './crypto';
import { VeilDisguise } from './disguise';
import type { OnboardingMode, ScannedItem } from './types';

(() => {
  let sidebarVisible = false;
  let sidebarFrame: HTMLIFrameElement | null = null;
  let sidebarContainer: HTMLDivElement | null = null;
  let pushStyleEl: HTMLStyleElement | null = null;
  let focusedInput: HTMLElement | null = null;
  let onboardingMode: OnboardingMode | null = null;
  let scanInterval: ReturnType<typeof setInterval> | null = null;
  const seenMessages = new Set<string>();

  const SIDEBAR_WIDTH = 360;

  // --- Sidebar Injection ---
  // Sidebar is appended to <html> (outside <body>).
  // Body gets `transform: translateX(0)` which creates a new containing block,
  // forcing all position:fixed children to be relative to body, not viewport.
  // Body width is constrained so everything inside shrinks — works on
  // Telegram, WhatsApp, and any fixed-layout app.

  function createSidebar(): void {
    if (sidebarContainer) return;

    pushStyleEl = document.createElement('style');
    pushStyleEl.id = 'veil-push-style';
    (document.head || document.documentElement).appendChild(pushStyleEl);

    sidebarContainer = document.createElement('div');
    sidebarContainer.id = 'veil-sidebar-container';

    sidebarFrame = document.createElement('iframe');
    sidebarFrame.src = chrome.runtime.getURL('sidebar.html');
    sidebarFrame.allow = 'clipboard-write';
    sidebarFrame.id = 'veil-sidebar-iframe';

    sidebarContainer.appendChild(sidebarFrame);
    document.documentElement.appendChild(sidebarContainer);

    applyLayout(true);
    sidebarVisible = true;
    startScanning();
  }

  function applyLayout(open: boolean): void {
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
      document.documentElement.classList.add('veil-sidebar-open');
    } else {
      document.documentElement.classList.remove('veil-sidebar-open');
    }
  }

  function toggleSidebar(): void {
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

  // --- Focus Detection (Tier 2) ---

  document.addEventListener(
    'focusin',
    (e) => {
      const el = e.target as HTMLElement;
      if (
        el.tagName === 'TEXTAREA' ||
        el.tagName === 'INPUT' ||
        el.getAttribute('contenteditable') === 'true' ||
        el.getAttribute('contenteditable') === ''
      ) {
        focusedInput = el;
      }
    },
    true,
  );

  // --- Onboarding: element selection ---

  function startOnboarding(phase: OnboardingMode): void {
    onboardingMode = phase;
    document.addEventListener('click', onboardingClickHandler, true);
  }

  function stopOnboarding(): void {
    onboardingMode = null;
    document.removeEventListener('click', onboardingClickHandler, true);
  }

  function onboardingClickHandler(e: MouseEvent): void {
    if (sidebarContainer && sidebarContainer.contains(e.target as Node)) return;

    e.preventDefault();
    e.stopPropagation();

    const el = e.target as HTMLElement;
    const selector = generateSelector(el);

    if (onboardingMode === 'input') {
      const hostname = window.location.hostname;
      chrome.storage.local.set({ [`veil_input_selector_${hostname}`]: selector }, () => {
        sendToSidebar({ type: 'ONBOARDING_INPUT_SAVED', selector });
      });
    } else if (onboardingMode === 'send') {
      const hostname = window.location.hostname;
      chrome.storage.local.set({ [`veil_send_selector_${hostname}`]: selector }, () => {
        sendToSidebar({ type: 'ONBOARDING_SEND_SAVED', selector });
      });
    }

    stopOnboarding();
  }

  function generateSelector(el: HTMLElement): string {
    if (el.id) return '#' + CSS.escape(el.id);

    const path: string[] = [];
    let current: HTMLElement | null = el;
    while (current && current !== document.body) {
      let seg = current.tagName.toLowerCase();
      if (current.id) {
        seg = '#' + CSS.escape(current.id);
        path.unshift(seg);
        break;
      }
      if (current.className && typeof current.className === 'string') {
        const classes = current.className.trim().split(/\s+/).slice(0, 2);
        if (classes.length > 0 && classes[0]) {
          seg += '.' + classes.map((c) => CSS.escape(c)).join('.');
        }
      }
      const parent = current.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter(
          (c) => c.tagName === current!.tagName,
        );
        if (siblings.length > 1) {
          const idx = siblings.indexOf(current) + 1;
          seg += `:nth-of-type(${idx})`;
        }
      }
      path.unshift(seg);
      current = current.parentElement;
    }
    return path.join(' > ');
  }

  // --- Input Injection (Tier 1 + Tier 2) ---

  async function injectAndSend(text: string): Promise<void> {
    const hostname = window.location.hostname;
    const data = await chrome.storage.local.get([
      `veil_input_selector_${hostname}`,
      `veil_send_selector_${hostname}`,
    ]);

    const inputSelector = data[`veil_input_selector_${hostname}`] as string | undefined;
    const sendSelector = data[`veil_send_selector_${hostname}`] as string | undefined;

    let inputEl: HTMLElement | null = inputSelector
      ? document.querySelector<HTMLElement>(inputSelector)
      : null;
    if (!inputEl) inputEl = focusedInput;

    if (!inputEl) {
      sendToSidebar({ type: 'INJECT_FAILED', text });
      return;
    }

    if (inputEl.getAttribute('contenteditable') !== null) {
      inputEl.focus();
      inputEl.innerHTML = '';
      inputEl.textContent = text;
      inputEl.dispatchEvent(new Event('input', { bubbles: true }));
      inputEl.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      inputEl.focus();
      (inputEl as HTMLInputElement | HTMLTextAreaElement).value = text;
      inputEl.dispatchEvent(new Event('input', { bubbles: true }));
      inputEl.dispatchEvent(new Event('change', { bubbles: true }));
    }

    await new Promise<void>((r) => setTimeout(r, 100));

    if (sendSelector) {
      const sendBtn = document.querySelector<HTMLElement>(sendSelector);
      if (sendBtn) {
        sendBtn.click();
        sendToSidebar({ type: 'INJECT_SUCCESS' });
        return;
      }
    }

    inputEl.dispatchEvent(
      new KeyboardEvent('keydown', {
        key: 'Enter',
        code: 'Enter',
        keyCode: 13,
        which: 13,
        bubbles: true,
      }),
    );

    sendToSidebar({ type: 'INJECT_SUCCESS' });
  }

  // --- Message Scanning (Phase 4) ---

  function startScanning(): void {
    if (scanInterval) return;
    scanMessages();
    scanInterval = setInterval(scanMessages, 2000);
  }

  function stopScanning(): void {
    if (scanInterval) {
      clearInterval(scanInterval);
      scanInterval = null;
    }
  }

  function scanMessages(): void {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);

    const found: ScannedItem[] = [];
    let node: Node | null;
    while ((node = walker.nextNode())) {
      const text = node.textContent;
      if (!text || text.length < 10) continue;

      if (sidebarContainer && sidebarContainer.contains(node)) continue;

      if (VeilDisguise.isVeilMessage(text)) {
        const payload = VeilDisguise.unwrapMessage(text);
        if (payload && !seenMessages.has(payload)) {
          seenMessages.add(payload);
          found.push({ type: 'encrypted', payload });
        }
      } else if (VeilDisguise.isHandshake(text)) {
        const data = VeilDisguise.unwrapHandshake(text);
        if (data && !seenMessages.has(data.publicKey)) {
          seenMessages.add(data.publicKey);
          found.push({ type: 'handshake', ...data });
        }
      } else if (VeilDisguise.isVerifyMessage(text)) {
        const payload = VeilDisguise.unwrapVerify(text);
        if (payload && !seenMessages.has(payload)) {
          seenMessages.add(payload);
          found.push({ type: 'verify', payload });
        }
      }
    }

    if (found.length > 0) {
      sendToSidebar({ type: 'SCANNED_MESSAGES', messages: found });
    }
  }

  // --- Communication ---

  function sendToSidebar(msg: Record<string, unknown>): void {
    if (sidebarFrame && sidebarFrame.contentWindow) {
      sidebarFrame.contentWindow.postMessage({ source: 'veil-content', ...msg }, '*');
    }
  }

  window.addEventListener('message', (e: MessageEvent) => {
    if (!e.data || e.data.source !== 'veil-sidebar') return;

    const msg = e.data as { type: string; text?: string };

    switch (msg.type) {
      case 'INJECT_TEXT':
        if (msg.text) injectAndSend(msg.text);
        break;
      case 'START_ONBOARDING_INPUT':
        startOnboarding('input');
        break;
      case 'START_ONBOARDING_SEND':
        startOnboarding('send');
        break;
      case 'SCAN_NOW':
        scanMessages();
        break;
    }
  });

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === 'TOGGLE_SIDEBAR') {
      toggleSidebar();
      sendResponse({ ok: true });
    }
  });

})();
