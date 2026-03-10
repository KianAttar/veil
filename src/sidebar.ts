// Veil — Sidebar logic
// Manages session state, crypto operations, and UI

import { VeilCrypto } from './crypto';
import { VeilDisguise } from './disguise';
import { t, setLang, getLang } from './i18n';
import type { ChatMessage, Language, PanelId, ScannedItem } from './types';

(() => {
  // --- State ---
  let currentPanel: PanelId | null = null;
  let previousPanel: PanelId | null = null;
  let sessionKey: CryptoKey | null = null;
  let myKeyPair: CryptoKeyPair | null = null;
  let myPublicKeyBase64: string | null = null;
  let theirPublicKeyBase64: string | null = null;
  let fingerprint: string | null = null;
  let verified = false;
  let messages: ChatMessage[] = [];
  let pendingReplyCode: string | null = null; // Stored when inject fails during handshake reply

  // --- Init ---

  async function init(): Promise<void> {
    chrome.storage.local.get(['veil_lang'], (data) => {
      if (data.veil_lang) {
        setLang(data.veil_lang as Language);
        applyLanguage();
        showPanel('panelNoSession');
      } else {
        showPanel('panelLang');
      }
    });

    bindEvents();
  }

  // --- i18n ---

  function applyLanguage(): void {
    const lang = getLang();
    const dir = lang === 'fa' ? 'rtl' : 'ltr';
    document.documentElement.dir = dir;
    document.documentElement.lang = lang === 'fa' ? 'fa' : 'en';

    document.querySelectorAll<HTMLElement>('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      if (key) el.textContent = t(key as Parameters<typeof t>[0]);
    });
    document.querySelectorAll<HTMLInputElement>('[data-i18n-placeholder]').forEach((el) => {
      const key = el.getAttribute('data-i18n-placeholder');
      if (key) el.placeholder = t(key as Parameters<typeof t>[0]);
    });
  }

  function setLanguage(lang: Language): void {
    setLang(lang);
    chrome.storage.local.set({ veil_lang: lang });
    applyLanguage();
  }

  // --- Panels ---

  function showPanel(id: PanelId): void {
    if (currentPanel && currentPanel !== id) {
      previousPanel = currentPanel;
    }
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    const panel = document.getElementById(id);
    if (panel) {
      panel.classList.add('active');
      currentPanel = id;
    }
    updateHeader();
  }

  function updateHeader(): void {
    const status = document.getElementById('headerStatus')!;
    if (currentPanel === 'panelSession' && verified) {
      status.textContent = t('verified') + ' \u2713';
      status.className = 'header-status verified';
    } else if (currentPanel === 'panelSession' && !verified) {
      status.textContent = t('waiting');
      status.className = 'header-status warning';
    } else if (currentPanel === 'panelHandshake') {
      status.textContent = t('waiting');
      status.className = 'header-status';
    } else {
      status.textContent = '';
      status.className = 'header-status';
    }
  }

  // --- Event Binding ---

  function bindEvents(): void {
    // Language picker
    document.querySelectorAll<HTMLButtonElement>('.lang-btn[data-lang]').forEach((btn) => {
      btn.addEventListener('click', () => {
        setLanguage(btn.dataset.lang as Language);
        showPanel('panelNoSession');
      });
    });

    // Start session (User A)
    document.getElementById('btnStartSession')!.addEventListener('click', startSession);

    // "I Received an Invite" (User B)
    document.getElementById('btnCompleteHandshake')!.addEventListener('click', () => {
      showPanel('panelHandshakeReceived');
    });

    // Copy invite code
    document.getElementById('btnCopyInvite')!.addEventListener('click', () => {
      const code = document.getElementById('inviteCode')!.textContent ?? '';
      copyToClipboard(code);
      showCopyFeedback('copyFeedback');
    });

    // Cancel handshake
    document.getElementById('btnCancelHandshake')!.addEventListener('click', () => {
      resetSession();
      showPanel('panelNoSession');
    });

    // Accept handshake (User B)
    document.getElementById('btnAcceptHandshake')!.addEventListener('click', acceptHandshake);

    // Submit reply manually (User A — manual paste of Bob's reply)
    document.getElementById('btnSubmitReply')!.addEventListener('click', submitReply);

    // Reject handshake
    document.getElementById('btnRejectHandshake')!.addEventListener('click', () => {
      showPanel('panelNoSession');
    });

    // Send message
    document.getElementById('btnSend')!.addEventListener('click', sendMessage);
    document.getElementById('composeInput')!.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });

    // Decrypt incoming (manual paste in session panel)
    document.getElementById('btnDecryptIncoming')!.addEventListener('click', decryptIncomingManual);

    // End session
    document.getElementById('btnEndSession')!.addEventListener('click', () => {
      resetSession();
      addSystemMessage(t('session_ended'));
      showPanel('panelNoSession');
    });

    // Settings
    document.getElementById('btnSettings')!.addEventListener('click', () => showPanel('panelSettings'));
    document.getElementById('btnSessionSettings')!.addEventListener('click', () => showPanel('panelSettings'));
    document.getElementById('btnBackFromSettings')!.addEventListener('click', () => {
      showPanel(previousPanel ?? (sessionKey ? 'panelSession' : 'panelNoSession'));
    });

    // Reset onboarding
    document.getElementById('btnResetOnboarding')!.addEventListener('click', startOnboardingFlow);

    // Manual decrypt (no-session panel)
    document.getElementById('btnManualDecrypt')!.addEventListener('click', manualDecrypt);

    // Copy fallback
    document.getElementById('btnCopyFallback')!.addEventListener('click', () => {
      const text = document.getElementById('fallbackText')!.textContent ?? '';
      copyToClipboard(text);
      showCopyFeedback('copyFallbackFeedback');
    });
    document.getElementById('btnBackFromFallback')!.addEventListener('click', () => {
      showPanel('panelSession');
    });

    // Skip onboarding
    document.getElementById('btnSkipOnboarding')!.addEventListener('click', () => {
      showPanel(sessionKey ? 'panelSession' : 'panelNoSession');
    });

    // Listen for messages from content script
    window.addEventListener('message', handleContentMessage);
  }

  // --- Session Flow ---

  async function startSession(): Promise<void> {
    try {
      myKeyPair = await VeilCrypto.generateKeyPair();
      myPublicKeyBase64 = await VeilCrypto.exportPublicKey(myKeyPair);
      const signature = await VeilCrypto.signProvenance(myPublicKeyBase64);

      const inviteWrapped = VeilDisguise.wrapHandshake(myPublicKeyBase64, signature);
      // Raw payload without zero-width markers — for manual copy/paste
      // Messengers strip invisible Unicode, so give users the clean version
      const inviteRaw = myPublicKeyBase64 + '.' + signature;

      document.getElementById('inviteCode')!.textContent = inviteRaw;
      showPanel('panelHandshake');

      // Auto-inject uses the wrapped version (with markers for auto-detection)
      sendToContent({ type: 'INJECT_TEXT', text: inviteWrapped });

      // Save keypair to session storage
      const privKeyExport = await VeilCrypto.exportPrivateKey(myKeyPair);
      chrome.storage.session.set({
        veil_private_key: privKeyExport,
        veil_public_key: myPublicKeyBase64,
        veil_role: 'initiator',
      });
    } catch (err) {
      console.error('Veil: startSession error', err);
    }
  }

  async function acceptHandshake(): Promise<void> {
    const errorEl = document.getElementById('handshakeError') as HTMLDivElement;
    errorEl.style.display = 'none';

    const pasteInput = document.getElementById('pasteInviteInput') as HTMLTextAreaElement;
    const rawInput = pasteInput.value.trim();
    if (!rawInput) return;

    // Try to extract handshake data from pasted text
    // Method 1: Full wrapped format (with zero-width markers intact)
    let handshakeData = VeilDisguise.unwrapHandshake(rawInput);

    // Method 2: Markers were stripped by messenger — try raw "publicKey.signature" format
    if (!handshakeData) {
      const cleaned = rawInput.replace(/[\u200B\u200C\u200D\uFEFF]/g, '').trim();
      const dotIdx = cleaned.indexOf('.');
      if (dotIdx > 0 && dotIdx < cleaned.length - 1) {
        handshakeData = {
          publicKey: cleaned.slice(0, dotIdx),
          signature: cleaned.slice(dotIdx + 1),
        };
      }
    }

    if (!handshakeData) {
      errorEl.textContent = 'Invalid invite code. Make sure you copied the full code.';
      errorEl.style.display = 'block';
      return;
    }

    const valid = await VeilCrypto.verifyProvenance(handshakeData.publicKey, handshakeData.signature);
    if (!valid) {
      errorEl.textContent = 'Invalid invite code. This does not appear to be from Veil.';
      errorEl.style.display = 'block';
      return;
    }

    const theirPubKey = handshakeData.publicKey;
    theirPublicKeyBase64 = theirPubKey;

    try {
      myKeyPair = await VeilCrypto.generateKeyPair();
      myPublicKeyBase64 = await VeilCrypto.exportPublicKey(myKeyPair);

      const theirKey = await VeilCrypto.importPublicKey(theirPubKey);
      sessionKey = await VeilCrypto.deriveSharedKey(myKeyPair.privateKey, theirKey);

      const signature = await VeilCrypto.signProvenance(myPublicKeyBase64);
      const replyString = VeilDisguise.wrapHandshake(myPublicKeyBase64, signature);

      fingerprint = await VeilCrypto.computeFingerprint(myPublicKeyBase64, theirPubKey);

      const verifyPayload = await VeilCrypto.encrypt(sessionKey, fingerprint);
      const verifyMsg = VeilDisguise.wrapVerify(verifyPayload);

      const combinedReply = replyString + verifyMsg;

      verified = true;

      const privKeyExport = await VeilCrypto.exportPrivateKey(myKeyPair);
      chrome.storage.session.set({
        veil_private_key: privKeyExport,
        veil_public_key: myPublicKeyBase64,
        veil_their_public_key: theirPubKey,
        veil_role: 'responder',
      });

      document.getElementById('fingerprintValue')!.textContent = fingerprint;
      document.getElementById('fingerprintSection')!.style.display = 'block';
      addSystemMessage(t('step3_desc'));

      pendingReplyCode = combinedReply;
      showPanel('panelSession');

      sendToContent({ type: 'INJECT_TEXT', text: combinedReply });
    } catch (err) {
      console.error('Veil: acceptHandshake error', err);
    }
  }

  async function submitReply(): Promise<void> {
    const input = document.getElementById('pasteReplyInput') as HTMLTextAreaElement;
    const errorEl = document.getElementById('replyError') as HTMLDivElement;
    const rawInput = input.value.trim();
    if (!rawInput || !myKeyPair) return;

    errorEl.style.display = 'none';

    let handshakeData = VeilDisguise.unwrapHandshake(rawInput);
    if (!handshakeData) {
      const cleaned = rawInput.replace(/[\u200B\u200C\u200D\uFEFF]/g, '').trim();
      const dotIdx = cleaned.indexOf('.');
      if (dotIdx > 0 && dotIdx < cleaned.length - 1) {
        handshakeData = {
          publicKey: cleaned.slice(0, dotIdx),
          signature: cleaned.slice(dotIdx + 1),
        };
      }
    }

    if (!handshakeData) {
      errorEl.textContent = 'Invalid reply code.';
      errorEl.style.display = 'block';
      return;
    }

    await completeHandshakeAsInitiator(handshakeData.publicKey);
  }

  async function completeHandshakeAsInitiator(theirPubKeyBase64: string): Promise<void> {
    try {
      const theirKey = await VeilCrypto.importPublicKey(theirPubKeyBase64);
      theirPublicKeyBase64 = theirPubKeyBase64;

      sessionKey = await VeilCrypto.deriveSharedKey(myKeyPair!.privateKey, theirKey);
      fingerprint = await VeilCrypto.computeFingerprint(myPublicKeyBase64!, theirPubKeyBase64);

      chrome.storage.session.set({ veil_their_public_key: theirPubKeyBase64 });

      document.getElementById('fingerprintValue')!.textContent = fingerprint;
      document.getElementById('fingerprintSection')!.style.display = 'block';

      // Wait for verify message (don't mark as verified yet)
      showPanel('panelSession');
    } catch (err) {
      console.error('Veil: completeHandshakeAsInitiator error', err);
    }
  }

  async function handleVerifyMessage(encryptedPayload: string): Promise<void> {
    if (!sessionKey) return;
    try {
      const receivedFingerprint = await VeilCrypto.decrypt(sessionKey, encryptedPayload);
      const expectedFingerprint = await VeilCrypto.computeFingerprint(
        theirPublicKeyBase64!,
        myPublicKeyBase64!,
      );

      if (receivedFingerprint === expectedFingerprint) {
        verified = true;
        addSystemMessage(t('fingerprint_match'));

        const stored = await getSessionStorage('veil_role');
        if (stored === 'initiator') {
          const myFp = await VeilCrypto.computeFingerprint(myPublicKeyBase64!, theirPublicKeyBase64!);
          const verifyPayload = await VeilCrypto.encrypt(sessionKey, myFp);
          const verifyMsg = VeilDisguise.wrapVerify(verifyPayload);
          sendToContent({ type: 'INJECT_TEXT', text: verifyMsg });
        }
      } else {
        verified = false;
        addSystemMessage(t('fingerprint_mismatch'));
      }
      updateHeader();
    } catch (err) {
      console.error('Veil: verify error', err);
    }
  }

  function resetSession(): void {
    sessionKey = null;
    myKeyPair = null;
    myPublicKeyBase64 = null;
    theirPublicKeyBase64 = null;
    fingerprint = null;
    verified = false;
    messages = [];
    renderMessages();

    chrome.storage.session.remove([
      'veil_private_key',
      'veil_public_key',
      'veil_their_public_key',
      'veil_session_key',
      'veil_role',
    ]);

    document.getElementById('fingerprintSection')!.style.display = 'none';
    updateHeader();
  }

  // --- Messaging ---

  async function sendMessage(): Promise<void> {
    const input = document.getElementById('composeInput') as HTMLTextAreaElement;
    const plaintext = input.value.trim();
    if (!plaintext || !sessionKey) return;

    try {
      const encrypted = await VeilCrypto.encrypt(sessionKey, plaintext);
      const wrapped = VeilDisguise.wrapMessage(encrypted);

      sendToContent({ type: 'INJECT_TEXT', text: wrapped });

      addMessage('you', plaintext);
      input.value = '';
      input.focus();
    } catch (err) {
      console.error('Veil: encrypt error', err);
    }
  }

  async function decryptIncoming(base64Payload: string): Promise<void> {
    if (!sessionKey) return;
    try {
      const plaintext = await VeilCrypto.decrypt(sessionKey, base64Payload);
      addMessage('them', plaintext);
    } catch (err) {
      console.error('Veil: decrypt error', err);
    }
  }

  async function decryptIncomingManual(): Promise<void> {
    const input = document.getElementById('pasteIncomingInput') as HTMLTextAreaElement;
    const text = input.value.trim();
    if (!text || !sessionKey) return;

    let payload = text;
    if (VeilDisguise.isVeilMessage(text)) {
      payload = VeilDisguise.unwrapMessage(text) ?? text;
    }

    try {
      const plaintext = await VeilCrypto.decrypt(sessionKey, payload);
      addMessage('them', plaintext);
      input.value = '';
    } catch {
      // Failed to decrypt — silently ignore
    }
  }

  async function manualDecrypt(): Promise<void> {
    const input = document.getElementById('manualDecryptInput') as HTMLInputElement;
    const resultEl = document.getElementById('manualDecryptResult') as HTMLParagraphElement;
    const text = input.value.trim();
    if (!text) return;

    let payload = text;
    if (VeilDisguise.isVeilMessage(text)) {
      payload = VeilDisguise.unwrapMessage(text) ?? text;
    }

    if (!sessionKey) {
      resultEl.textContent = 'No active session key.';
      return;
    }

    try {
      const plaintext = await VeilCrypto.decrypt(sessionKey, payload);
      resultEl.textContent = plaintext;
      resultEl.style.color = 'var(--success)';
    } catch {
      resultEl.textContent = 'Decryption failed.';
      resultEl.style.color = 'var(--danger)';
    }
  }

  // --- Messages UI ---

  function addMessage(sender: ChatMessage['sender'], text: string): void {
    messages.push({ sender, text });
    renderMessages();
  }

  function addSystemMessage(text: string): void {
    messages.push({ sender: 'system', text });
    renderMessages();
  }

  function renderMessages(): void {
    const list = document.getElementById('messagesList')!;
    list.innerHTML = '';

    messages.forEach((msg) => {
      const div = document.createElement('div');
      if (msg.sender === 'you') {
        div.className = 'msg msg-you';
        div.textContent = msg.text;
      } else if (msg.sender === 'them') {
        div.className = 'msg msg-them';
        div.textContent = msg.text;
      } else {
        div.className = 'msg msg-system';
        div.textContent = msg.text;
      }
      list.appendChild(div);
    });

    list.scrollTop = list.scrollHeight;
  }

  // --- Onboarding ---

  function startOnboardingFlow(): void {
    showPanel('panelOnboarding');
    document.getElementById('onboardingPrompt')!.textContent = t('onboarding_input');
    sendToContent({ type: 'START_ONBOARDING_INPUT' });
  }

  // --- Communication with content script ---

  function sendToContent(msg: Record<string, unknown>): void {
    window.parent.postMessage({ source: 'veil-sidebar', ...msg }, '*');
  }

  function handleContentMessage(e: MessageEvent): void {
    if (!e.data || e.data.source !== 'veil-content') return;
    const msg = e.data as {
      type: string;
      text?: string;
      selector?: string;
      messages?: ScannedItem[];
    };

    switch (msg.type) {
      case 'INJECT_FAILED':
        // During handshake, the invite code is already shown with a copy button
        if (currentPanel === 'panelHandshake') {
          break;
        }
        // If we just completed handshake as responder, show reply code to copy
        if (pendingReplyCode && currentPanel === 'panelSession') {
          addSystemMessage(t('copy_fallback'));
          addSystemMessage(pendingReplyCode);
          pendingReplyCode = null;
          break;
        }
        // Show copy fallback for regular messages
        document.getElementById('fallbackText')!.textContent = msg.text ?? '';
        showPanel('panelCopyFallback');
        break;

      case 'INJECT_SUCCESS':
        // Good, nothing to do
        break;

      case 'ONBOARDING_INPUT_SAVED':
        document.getElementById('onboardingPrompt')!.textContent = t('onboarding_send');
        sendToContent({ type: 'START_ONBOARDING_SEND' });
        break;

      case 'ONBOARDING_SEND_SAVED':
        document.getElementById('onboardingPrompt')!.textContent = t('onboarding_done');
        setTimeout(() => {
          showPanel(sessionKey ? 'panelSession' : 'panelNoSession');
        }, 1500);
        break;

      case 'SCANNED_MESSAGES':
        if (msg.messages) handleScannedMessages(msg.messages);
        break;
    }
  }

  async function handleScannedMessages(scannedMessages: ScannedItem[]): Promise<void> {
    for (const msg of scannedMessages) {
      if (msg.type === 'handshake') {
        const valid = await VeilCrypto.verifyProvenance(msg.publicKey, msg.signature);
        if (!valid) {
          console.warn('Veil: invalid provenance on handshake');
          continue;
        }

        // Only auto-process if we are the initiator waiting for a reply
        if (currentPanel === 'panelHandshake' && myKeyPair) {
          if (msg.publicKey !== myPublicKeyBase64) {
            await completeHandshakeAsInitiator(msg.publicKey);
          }
        }
        // User B flow is manual (paste) — no auto-detection needed
      } else if (msg.type === 'encrypted') {
        await decryptIncoming(msg.payload);
      } else if (msg.type === 'verify') {
        await handleVerifyMessage(msg.payload);
      }
    }
  }

  // --- Utilities ---

  function copyToClipboard(text: string): void {
    navigator.clipboard.writeText(text).catch(() => {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    });
  }

  function showCopyFeedback(elementId: string): void {
    const el = document.getElementById(elementId)!;
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 1500);
  }

  function getSessionStorage(key: string): Promise<string | null> {
    return new Promise((resolve) => {
      chrome.storage.session.get([key], (data) => {
        resolve((data[key] as string) ?? null);
      });
    });
  }

  // --- Boot ---
  init();
})();
