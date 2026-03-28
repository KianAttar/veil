// Veil — Content script (v2: overlay-based architecture)
// Handles: session state, automatic handshake, MutationObserver,
// DOM text replacement, send interception, onboarding.

import { VeilCrypto } from './crypto';
import { VeilDisguise } from './disguise';
import { VERIFY_SERVER_URL } from './config';
import type { HandshakePayload, OnboardingMode } from './types';

(() => {
  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  type HandshakeState = 'idle' | 'invited' | 'established';

  let handshakeState: HandshakeState = 'idle';
  let sessionKey: CryptoKey | null = null;
  let myKeyPair: CryptoKeyPair | null = null;
  let myPublicKeyBase64: string | null = null;
  let theirPublicKeyBase64: string | null = null;
  let myNonce: string | null = null;
  let establishedAt: number = 0;
  let fingerprint: string | null = null;

  let sessionEndedAt: number = 0; // timestamp of last session end — ignore older messages
  let lastEncryptedOutgoing: string | null = null;

  // Verification status — displayed in popup
  type VerifyStatus = 'pending' | 'verified' | 'failed' | 'error';
  let inBandVerify: VerifyStatus = 'pending';
  let serverVerify: VerifyStatus = 'pending';
  let serverVerifyError: string | null = null;
  let onboardingMode: OnboardingMode | null = null;
  let observer: MutationObserver | null = null;

  // Track nodes we've already processed to avoid re-processing loops
  const processedNodes = new WeakSet<Node>();
  const seenPayloads = new Set<string>();

  // ---------------------------------------------------------------------------
  // DOM annotation — append translation/status below original Veil payload
  // ---------------------------------------------------------------------------

  let annotationStyleInjected = false;

  function injectAnnotationStyle(): void {
    if (annotationStyleInjected) return;
    annotationStyleInjected = true;
    const style = document.createElement('style');
    style.textContent = `
      .veil-annotation {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        margin-top: 4px;
      }
      .veil-sep {
        display: block;
        font-size: 10px;
        letter-spacing: 2px;
        color: #6c63ff;
        opacity: 0.6;
        user-select: none;
      }
      .veil-msg {
        display: block;
        font-size: 13px;
        margin-top: 2px;
      }
      .veil-msg.success { color: #2ed573; }
      .veil-msg.error   { color: #ff4757; }
      .veil-msg.info    { color: #a0a0b8; }
    `;
    document.head.appendChild(style);
  }

  function annotateVeilNode(node: Node, message: string, type: 'success' | 'error' | 'info' = 'info'): void {
    injectAnnotationStyle();
    const parent = node.parentElement;
    if (!parent) return;

    const annotation = document.createElement('div');
    annotation.className = 'veil-annotation';

    const sep = document.createElement('span');
    sep.className = 'veil-sep';
    sep.textContent = '---VEIL---';

    const msg = document.createElement('span');
    msg.className = `veil-msg ${type}`;
    msg.textContent = message;

    annotation.appendChild(sep);
    annotation.appendChild(msg);

    // Insert after the text node (or after previous annotations)
    let insertBefore = node.nextSibling;
    while (insertBefore instanceof HTMLElement && insertBefore.classList.contains('veil-annotation')) {
      insertBefore = insertBefore.nextSibling;
    }
    parent.insertBefore(annotation, insertBefore);
  }

  // ---------------------------------------------------------------------------
  // Storage helpers
  // ---------------------------------------------------------------------------

  function saveSessionToStorage(): void {
    if (!myKeyPair || !myPublicKeyBase64) return;
    VeilCrypto.exportPrivateKey(myKeyPair).then((privKey) => {
      const data: Record<string, unknown> = {
        veil_handshake_state: handshakeState,
        veil_private_key: privKey,
        veil_public_key: myPublicKeyBase64,
        veil_nonce: myNonce,
        veil_established_at: establishedAt,
      };
      if (theirPublicKeyBase64) data.veil_their_public_key = theirPublicKeyBase64;
      if (fingerprint) data.veil_fingerprint = fingerprint;
      console.log('Veil: saving session to storage, state=%s', handshakeState);
      chrome.storage.session.set(data, () => {
        if (chrome.runtime.lastError) {
          console.error('Veil: storage.session.set failed:', chrome.runtime.lastError.message);
        } else {
          console.log('Veil: session saved successfully');
        }
      });
    }).catch((err) => {
      console.error('Veil: exportPrivateKey failed:', err);
    });
  }

  function clearSession(): void {
    handshakeState = 'idle';
    sessionKey = null;
    myKeyPair = null;
    myPublicKeyBase64 = null;
    theirPublicKeyBase64 = null;
    myNonce = null;
    establishedAt = 0;
    fingerprint = null;
    // NOTE: do NOT clear sessionEndedAt — it must persist to filter stale messages
    seenPayloads.clear();
    inBandVerify = 'pending';
    serverVerify = 'pending';
    serverVerifyError = null;

    chrome.storage.session.remove([
      'veil_handshake_state',
      'veil_private_key',
      'veil_public_key',
      'veil_their_public_key',
      'veil_nonce',
      'veil_established_at',
      'veil_fingerprint',
    ]);

    removeVeilToggle();
  }

  async function endSession(): Promise<void> {
    // Send [VL:X] so the peer also ends their session
    if (sessionKey) {
      try {
        const ts = nowSeconds().toString();
        const encrypted = await VeilCrypto.encrypt(sessionKey, ts);
        const wrapped = VeilDisguise.wrapEnd(encrypted);
        await injectAndSend(wrapped);
      } catch (err) {
        console.error('Veil: failed to send end signal', err);
      }
    }
    sessionEndedAt = nowSeconds();
    clearSession();
    showToast('Session ended', 'info');
  }

  async function restoreSession(): Promise<void> {
    return new Promise((resolve) => {
      chrome.storage.session.get([
        'veil_handshake_state',
        'veil_private_key',
        'veil_public_key',
        'veil_their_public_key',
        'veil_nonce',
        'veil_established_at',
        'veil_fingerprint',
      ], async (data) => {
        if (!data) { resolve(); return; }
        const state = data.veil_handshake_state as HandshakeState | undefined;
        if (!state || state === 'idle' || !data.veil_private_key || !data.veil_public_key) {
          resolve();
          return;
        }

        try {
          const privateKey = await VeilCrypto.importPrivateKey(data.veil_private_key as string);
          const publicKey = await VeilCrypto.importPublicKey(data.veil_public_key as string);
          myKeyPair = { privateKey, publicKey } as CryptoKeyPair;
          myPublicKeyBase64 = data.veil_public_key as string;
          myNonce = (data.veil_nonce as string) ?? null;
          establishedAt = (data.veil_established_at as number) ?? 0;
          fingerprint = (data.veil_fingerprint as string) ?? null;
          handshakeState = state;

          if (state === 'established' && data.veil_their_public_key) {
            theirPublicKeyBase64 = data.veil_their_public_key as string;
            const theirKey = await VeilCrypto.importPublicKey(theirPublicKeyBase64);
            sessionKey = await VeilCrypto.deriveSharedKey(myKeyPair.privateKey, theirKey);
            showVeilToggle();
          }
        } catch (err) {
          console.error('Veil: failed to restore session', err);
          clearSession();
        }
        resolve();
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Nonce generation
  // ---------------------------------------------------------------------------

  function generateNonce(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function nowSeconds(): number {
    return Math.floor(Date.now() / 1000);
  }

  // ---------------------------------------------------------------------------
  // Handshake: start session
  // ---------------------------------------------------------------------------

  async function startSession(): Promise<void> {
    // Step 1: Scan chat for existing invites (< 10 min old)
    const existingInvite = scanForInvite();
    if (existingInvite) {
      await acceptInvite(existingInvite);
      return;
    }

    // Step 2: No invite found — create our own
    myKeyPair = await VeilCrypto.generateKeyPair();
    myPublicKeyBase64 = await VeilCrypto.exportPublicKey(myKeyPair);
    const sig = await VeilCrypto.signProvenance(myPublicKeyBase64);
    myNonce = generateNonce();
    const ts = nowSeconds();

    const wrapped = VeilDisguise.wrapInvite(myPublicKeyBase64, sig, myNonce, ts);
    handshakeState = 'invited';
    saveSessionToStorage();

    await injectAndSend(wrapped);
  }

  // ---------------------------------------------------------------------------
  // Handshake: scan for existing invite
  // ---------------------------------------------------------------------------

  function scanForInvite(): HandshakePayload | null {
    // Ignore invites older than 10 min OR older than the last session end
    const cutoff = Math.max(nowSeconds() - 600, sessionEndedAt);
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    let node: Node | null;
    let best: HandshakePayload | null = null;

    while ((node = walker.nextNode())) {
      const text = node.textContent;
      if (!text || text.length < 10) continue;
      if (!VeilDisguise.isInvite(text)) continue;

      const data = VeilDisguise.unwrapInvite(text);
      if (!data) continue;
      if (data.timestamp <= cutoff) continue;
      if (data.publicKey === myPublicKeyBase64) continue; // own message

      // Take the most recent invite
      if (!best || data.timestamp > best.timestamp) {
        best = data;
      }
    }
    return best;
  }

  // ---------------------------------------------------------------------------
  // Handshake: accept an invite
  // ---------------------------------------------------------------------------

  async function acceptInvite(invite: HandshakePayload): Promise<void> {
    // Verify provenance
    try {
      const valid = await VeilCrypto.verifyProvenance(invite.publicKey, invite.signature);
      if (!valid) {
        console.warn('Veil: invalid provenance on invite');
        return;
      }

      // Generate our keypair
      myKeyPair = await VeilCrypto.generateKeyPair();
      myPublicKeyBase64 = await VeilCrypto.exportPublicKey(myKeyPair);
      theirPublicKeyBase64 = invite.publicKey;

      // Derive shared key
      const theirKey = await VeilCrypto.importPublicKey(theirPublicKeyBase64);
      sessionKey = await VeilCrypto.deriveSharedKey(myKeyPair.privateKey, theirKey);

      // Compute fingerprint
      fingerprint = await VeilCrypto.computeFingerprint(myPublicKeyBase64, theirPublicKeyBase64);

      // Send reply echoing their nonce
      const sig = await VeilCrypto.signProvenance(myPublicKeyBase64);
      const reply = VeilDisguise.wrapReply(myPublicKeyBase64, sig, invite.nonce, nowSeconds());

      // Send verify
      const verifyPayload = await VeilCrypto.encrypt(sessionKey, fingerprint);
      const verify = VeilDisguise.wrapVerify(verifyPayload);

      handshakeState = 'established';
      establishedAt = nowSeconds();
      saveSessionToStorage();
      showVeilToggle();

      await injectAndSend(reply + verify);

      // Out-of-band verification (non-blocking)
      verifyViaServer();
    } catch (err) {
      console.error('Veil: acceptInvite error', err);
    }
  }

  // ---------------------------------------------------------------------------
  // Handshake: complete as initiator (received reply)
  // ---------------------------------------------------------------------------

  async function completeHandshake(reply: HandshakePayload): Promise<void> {
    try {
      const valid = await VeilCrypto.verifyProvenance(reply.publicKey, reply.signature);
      if (!valid) {
        console.warn('Veil: invalid provenance on reply');
        return;
      }

      theirPublicKeyBase64 = reply.publicKey;
      const theirKey = await VeilCrypto.importPublicKey(theirPublicKeyBase64);
      sessionKey = await VeilCrypto.deriveSharedKey(myKeyPair!.privateKey, theirKey);
      fingerprint = await VeilCrypto.computeFingerprint(myPublicKeyBase64!, theirPublicKeyBase64);

      handshakeState = 'established';
      establishedAt = nowSeconds();
      saveSessionToStorage();
      showVeilToggle();

      // Send our verify message
      const verifyPayload = await VeilCrypto.encrypt(sessionKey, fingerprint);
      const verify = VeilDisguise.wrapVerify(verifyPayload);
      await injectAndSend(verify);

      // Out-of-band verification (non-blocking)
      verifyViaServer();
    } catch (err) {
      console.error('Veil: completeHandshake error', err);
    }
  }

  // ---------------------------------------------------------------------------
  // Verify fingerprint (in-band)
  // ---------------------------------------------------------------------------

  async function handleVerify(node: Node, encryptedPayload: string): Promise<void> {
    if (!sessionKey || !theirPublicKeyBase64 || !myPublicKeyBase64) {
      annotateVeilNode(node, 'Cannot verify — no active session', 'error');
      return;
    }
    try {
      const received = await VeilCrypto.decrypt(sessionKey, encryptedPayload);
      const expected = await VeilCrypto.computeFingerprint(theirPublicKeyBase64, myPublicKeyBase64);
      if (received !== expected) {
        console.warn('Veil: fingerprint mismatch — possible MITM');
        showToast('Fingerprint mismatch! Possible MITM attack.', 'danger');
        annotateVeilNode(node, 'Fingerprint MISMATCH — possible MITM!', 'error');
        inBandVerify = 'failed';
      } else {
        annotateVeilNode(node, 'Fingerprint verified: ' + received, 'success');
        inBandVerify = 'verified';
      }
    } catch (err) {
      console.error('Veil: verify error', err);
      annotateVeilNode(node, 'Verification failed — decrypt error', 'error');
      inBandVerify = 'error';
    }
  }

  // ---------------------------------------------------------------------------
  // Verify fingerprint (out-of-band via server)
  // ---------------------------------------------------------------------------

  async function verifyViaServer(): Promise<void> {
    if (!fingerprint || !myPublicKeyBase64 || !theirPublicKeyBase64) return;

    const url = VERIFY_SERVER_URL;
    console.log('Veil: server verification — posting fingerprint to %s', url);

    // POST our fingerprint
    try {
      const resp = await fetch(`${url}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          publicKey: myPublicKeyBase64,
          fingerprint,
        }),
      });
      if (!resp.ok) {
        console.error('Veil: verify server POST failed: %d', resp.status);
        serverVerify = 'error';
        serverVerifyError = 'Server returned ' + resp.status;
        return;
      }
    } catch (err) {
      console.warn('Veil: verify server unreachable — skipping server verification', err);
      serverVerify = 'error';
      serverVerifyError = 'Server unreachable';
      return;
    }

    // GET peer's fingerprint — retry a few times (peer may not have posted yet)
    const maxAttempts = 5;
    const retryDelay = 2000;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const resp = await fetch(
          `${url}/verify?publicKey=${encodeURIComponent(theirPublicKeyBase64)}`,
        );
        const data = await resp.json() as { found: boolean; fingerprint?: string };

        if (!data.found) {
          console.log('Veil: server verification — peer not found yet (attempt %d/%d)', attempt, maxAttempts);
          await new Promise<void>((r) => setTimeout(r, retryDelay));
          continue;
        }

        if (data.fingerprint === fingerprint) {
          console.log('Veil: server verification PASSED — no MITM');
          showToast('Server verified — no MITM detected', 'success');
          serverVerify = 'verified';
        } else {
          console.warn('Veil: SERVER VERIFICATION FAILED — fingerprint mismatch! theirs=%s ours=%s', data.fingerprint, fingerprint);
          showToast('SERVER VERIFICATION FAILED — possible MITM!', 'danger');
          serverVerify = 'failed';
          serverVerifyError = 'Peer fingerprint: ' + data.fingerprint;
        }
        return;
      } catch (err) {
        console.error('Veil: verify server GET failed', err);
        serverVerify = 'error';
        serverVerifyError = 'Network error';
        return;
      }
    }

    console.warn('Veil: server verification — peer never posted (timed out)');
    serverVerify = 'error';
    serverVerifyError = 'Peer not found (timed out)';
  }

  // ---------------------------------------------------------------------------
  // MutationObserver — detect & process Veil messages
  // ---------------------------------------------------------------------------

  function startObserver(): void {
    if (observer) return;

    // Initial scan of existing DOM
    scanExistingNodes();

    let mutationCount = 0;
    observer = new MutationObserver((mutations) => {
      mutationCount++;
      console.log('Veil: MutationObserver fired, batch #%d, %d mutations', mutationCount, mutations.length);
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          processNode(node);
        });
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
    console.log('Veil: MutationObserver started');
  }

  function stopObserver(): void {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
  }

  function scanExistingNodes(): void {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    let node: Node | null;
    while ((node = walker.nextNode())) {
      processTextNode(node);
    }
  }

  function processNode(node: Node): void {
    if (node.nodeType === Node.TEXT_NODE) {
      processTextNode(node);
      return;
    }
    if (node.nodeType === Node.ELEMENT_NODE) {
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, null);
      let child: Node | null;
      while ((child = walker.nextNode())) {
        processTextNode(child);
      }
    }
  }

  function processTextNode(node: Node): void {
    const text = node.textContent;
    if (!text || text.length < 10) return;
    if (processedNodes.has(node)) return;
    if (!VeilDisguise.isAnyVeil(text)) return;

    // Don't process nodes inside our own UI
    const toggle = document.getElementById('veil-toggle-container');
    if (toggle && toggle.contains(node)) return;
    const toast = document.getElementById('veil-toast');
    if (toast && toast.contains(node)) return;

    processedNodes.add(node);
    console.log('Veil: processTextNode — state=%s, hasI=%s, hasR=%s, hasE=%s, hasV=%s, hasX=%s, len=%d',
      handshakeState,
      VeilDisguise.isInvite(text), VeilDisguise.isReply(text),
      VeilDisguise.isVeilMessage(text), VeilDisguise.isVerifyMessage(text),
      VeilDisguise.isEndMessage(text),
      text.length);

    // A single text node may contain multiple Veil tags (e.g. reply + verify).
    // Check each type independently rather than using exclusive if/else.
    // End signal checked first — if session is ending, skip other processing.
    if (VeilDisguise.isEndMessage(text)) {
      handleEndNode(node, text);
      return; // session is over — don't process other tags in same node
    }
    if (VeilDisguise.isVeilMessage(text)) {
      handleEncryptedNode(node, text);
    }
    if (VeilDisguise.isInvite(text)) {
      handleInviteNode(node, text);
    }
    if (VeilDisguise.isReply(text)) {
      handleReplyNode(node, text);
    }
    if (VeilDisguise.isVerifyMessage(text)) {
      handleVerifyNode(node, text);
    }
  }

  // --- Handle encrypted message in DOM ---

  async function handleEncryptedNode(node: Node, text: string): Promise<void> {
    if (!sessionKey) {
      annotateVeilNode(node, 'No active session — cannot decrypt', 'error');
      return;
    }
    const payload = VeilDisguise.unwrapMessage(text);
    if (!payload || seenPayloads.has(payload)) return;
    seenPayloads.add(payload);

    try {
      const plaintext = await VeilCrypto.decrypt(sessionKey, payload);
      annotateVeilNode(node, '\u{1F512} ' + plaintext, 'success');
    } catch {
      annotateVeilNode(node, 'Could not decrypt — wrong session or corrupted', 'error');
    }
  }

  // --- Handle invite ---

  function handleInviteNode(node: Node, text: string): void {
    const data = VeilDisguise.unwrapInvite(text);
    if (!data) return;
    if (data.timestamp <= sessionEndedAt) {
      annotateVeilNode(node, 'Stale invite — from ended session', 'info');
      return;
    }
    if (data.publicKey === myPublicKeyBase64) {
      annotateVeilNode(node, 'Your handshake invite — waiting for response', 'info');
      return;
    }

    const key = `invite:${data.publicKey}`;
    if (seenPayloads.has(key)) return;
    seenPayloads.add(key);

    if (handshakeState === 'idle') {
      annotateVeilNode(node, 'Handshake invite — start a session to accept', 'info');
      return;
    }

    if (handshakeState === 'invited') {
      // Both sides started at the same time — accept theirs
      annotateVeilNode(node, 'Handshake invite — accepting...', 'info');
      acceptInvite(data);
      return;
    }

    if (handshakeState === 'established') {
      if (data.timestamp <= establishedAt) {
        annotateVeilNode(node, 'Old handshake invite — ignored', 'info');
        return;
      }

      if (confirm('Veil: New connection request received. Accept and reset current session?')) {
        clearSession();
        acceptInvite(data);
      } else {
        annotateVeilNode(node, 'Handshake invite — declined', 'info');
      }
    }
  }

  // --- Handle reply ---

  async function handleReplyNode(node: Node, text: string): Promise<void> {
    const data = VeilDisguise.unwrapReply(text);
    if (!data) { console.log('Veil: handleReplyNode — unwrap failed'); return; }
    if (data.timestamp <= sessionEndedAt) {
      annotateVeilNode(node, 'Stale reply — from ended session', 'info');
      return;
    }
    if (data.publicKey === myPublicKeyBase64) {
      console.log('Veil: handleReplyNode — own message');
      annotateVeilNode(node, 'Your handshake reply', 'info');
      return;
    }

    const key = `reply:${data.publicKey}`;
    if (seenPayloads.has(key)) { console.log('Veil: handleReplyNode — already seen'); return; }
    seenPayloads.add(key);

    if (handshakeState !== 'invited') {
      console.log('Veil: handleReplyNode — not invited, state=%s', handshakeState);
      annotateVeilNode(node, 'Handshake reply — no pending invite', 'info');
      return;
    }
    if (data.nonce !== myNonce) {
      console.log('Veil: handleReplyNode — nonce mismatch: %s vs %s', data.nonce, myNonce);
      annotateVeilNode(node, 'Handshake reply — nonce mismatch', 'error');
      return;
    }

    console.log('Veil: handleReplyNode — completing handshake');
    await completeHandshake(data);
    annotateVeilNode(node, 'Handshake complete — session established', 'success');

    // Reply+verify are often in the same text node — process verify now
    if (VeilDisguise.isVerifyMessage(text)) {
      handleVerifyNode(node, text);
    }
  }

  // --- Handle verify ---

  function handleVerifyNode(node: Node, text: string): void {
    const payload = VeilDisguise.unwrapVerify(text);
    if (!payload) return;
    if (seenPayloads.has(`verify:${payload}`)) return;
    seenPayloads.add(`verify:${payload}`);

    handleVerify(node, payload);
  }

  // --- Handle end session ---

  async function handleEndNode(node: Node, text: string): Promise<void> {
    const payload = VeilDisguise.unwrapEnd(text);
    if (!payload) return;
    if (seenPayloads.has(`end:${payload}`)) return;
    seenPayloads.add(`end:${payload}`);

    if (!sessionKey) {
      annotateVeilNode(node, 'Session end signal', 'info');
      return;
    }

    try {
      const tsStr = await VeilCrypto.decrypt(sessionKey, payload);
      const ts = parseInt(tsStr, 10);
      if (isNaN(ts)) {
        annotateVeilNode(node, 'Session end signal — invalid', 'error');
        return;
      }
      sessionEndedAt = ts;
      clearSession();
      showToast('Peer ended the session', 'info');
      annotateVeilNode(node, 'Session ended by peer', 'error');
    } catch {
      annotateVeilNode(node, 'Session end signal — could not verify', 'error');
    }
  }

  // ---------------------------------------------------------------------------
  // Input injection
  // ---------------------------------------------------------------------------

  async function getInputSelector(): Promise<{ inputSelector?: string; sendSelector?: string }> {
    const hostname = window.location.hostname;
    return new Promise((resolve) => {
      chrome.storage.local.get([
        `veil_input_selector_${hostname}`,
        `veil_send_selector_${hostname}`,
      ], (data) => {
        if (!data) { resolve({}); return; }
        resolve({
          inputSelector: data[`veil_input_selector_${hostname}`] as string | undefined,
          sendSelector: data[`veil_send_selector_${hostname}`] as string | undefined,
        });
      });
    });
  }

  async function injectAndSend(text: string): Promise<void> {
    const { inputSelector, sendSelector } = await getInputSelector();
    const inputEl = inputSelector ? document.querySelector<HTMLElement>(inputSelector) : null;
    if (!inputEl) {
      console.warn('Veil: no input element found — cannot inject');
      return;
    }

    // Type into input
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

    // Click send button or press Enter
    if (sendSelector) {
      const sendBtn = document.querySelector<HTMLElement>(sendSelector);
      if (sendBtn) {
        sendBtn.click();
        return;
      }
    }

    inputEl.dispatchEvent(
      new KeyboardEvent('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true,
      }),
    );
  }

  // ---------------------------------------------------------------------------
  // Send interception: "Veil: ON" toggle
  // ---------------------------------------------------------------------------

  let veilEnabled = false;

  function showVeilToggle(): void {
    if (document.getElementById('veil-toggle-container')) return;

    getInputSelector().then(({ inputSelector }) => {
      if (!inputSelector) return;
      const inputEl = document.querySelector<HTMLElement>(inputSelector);
      if (!inputEl) return;

      // Add toggle styles to head (not inside the container)
      const style = document.createElement('style');
      style.textContent = `
        #veil-toggle-container {
          position: fixed;
          z-index: 2147483647;
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 4px 10px;
          border-radius: 16px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          font-size: 12px;
          font-weight: 600;
          cursor: pointer;
          user-select: none;
          transition: background 0.2s, color 0.2s;
          pointer-events: auto;
        }
        #veil-toggle-container.enabled {
          background: rgba(46, 213, 115, 0.15);
          color: #2ed573;
          border: 1px solid rgba(46, 213, 115, 0.3);
        }
        #veil-toggle-container.disabled {
          background: rgba(136, 136, 160, 0.15);
          color: #8888a0;
          border: 1px solid rgba(136, 136, 160, 0.3);
        }
      `;
      document.head.appendChild(style);

      const container = document.createElement('div');
      container.id = 'veil-toggle-container';
      container.title = 'When ON, pressing Enter encrypts your message before sending';
      container.innerHTML = `
        <span id="veil-toggle-icon"></span>
        <span id="veil-toggle-label"></span>
      `;

      document.body.appendChild(container);

      // Position near input
      function positionToggle(): void {
        const rect = inputEl!.getBoundingClientRect();
        container.style.top = `${rect.top - 30}px`;
        container.style.right = `${window.innerWidth - rect.right}px`;
      }
      positionToggle();

      // Re-position on scroll/resize
      window.addEventListener('scroll', positionToggle, { passive: true });
      window.addEventListener('resize', positionToggle, { passive: true });

      // Toggle on click
      veilEnabled = true;
      updateToggleUI();
      container.addEventListener('click', () => {
        veilEnabled = !veilEnabled;
        updateToggleUI();
      });

      // Intercept send
      setupSendInterception(inputSelector);
    });
  }

  function removeVeilToggle(): void {
    const el = document.getElementById('veil-toggle-container');
    if (el) el.remove();
    veilEnabled = false;
  }

  function updateToggleUI(): void {
    const container = document.getElementById('veil-toggle-container');
    if (!container) return;
    const icon = document.getElementById('veil-toggle-icon')!;
    const label = document.getElementById('veil-toggle-label')!;

    if (veilEnabled) {
      container.className = 'enabled';
      icon.textContent = '\u{1F512}';
      label.textContent = 'Veil: ON';
    } else {
      container.className = 'disabled';
      icon.textContent = '\u{1F513}';
      label.textContent = 'Veil: OFF';
    }
  }

  function setupSendInterception(inputSelector: string): void {
    // Intercept Enter key on the input
    document.addEventListener('keydown', async (e) => {
      if (!veilEnabled || !sessionKey) return;
      if (e.key !== 'Enter' || e.shiftKey) return;

      const target = e.target as HTMLElement;
      const inputEl = document.querySelector<HTMLElement>(inputSelector);
      if (!inputEl || target !== inputEl) return;

      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      // Read input text
      let plaintext = '';
      if (inputEl.getAttribute('contenteditable') !== null) {
        plaintext = (inputEl.textContent ?? '').trim();
      } else {
        plaintext = ((inputEl as HTMLInputElement | HTMLTextAreaElement).value ?? '').trim();
      }

      if (!plaintext) return;

      try {
        // Encrypt
        const ciphertext = await VeilCrypto.encrypt(sessionKey, plaintext);
        const wrapped = VeilDisguise.wrapMessage(ciphertext);
        lastEncryptedOutgoing = wrapped;

        // Replace input text with ciphertext
        if (inputEl.getAttribute('contenteditable') !== null) {
          inputEl.innerHTML = '';
          inputEl.textContent = wrapped;
          inputEl.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
          (inputEl as HTMLInputElement | HTMLTextAreaElement).value = wrapped;
          inputEl.dispatchEvent(new Event('input', { bubbles: true }));
        }

        await new Promise<void>((r) => setTimeout(r, 50));

        // Send via button or Enter
        const { sendSelector } = await getInputSelector();
        if (sendSelector) {
          const sendBtn = document.querySelector<HTMLElement>(sendSelector);
          if (sendBtn) {
            sendBtn.click();
            return;
          }
        }

        inputEl.dispatchEvent(
          new KeyboardEvent('keydown', {
            key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true,
          }),
        );
      } catch (err) {
        console.error('Veil: encrypt/send error', err);
      }
    }, true); // capture phase
  }

  // ---------------------------------------------------------------------------
  // Onboarding
  // ---------------------------------------------------------------------------

  function startOnboarding(): void {
    onboardingMode = 'input';
    showToast('Type something in the chat input...', 'info');
    document.addEventListener('input', onboardingInputHandler, true);
  }

  function onboardingInputHandler(e: Event): void {
    if (onboardingMode !== 'input') return;

    const el = e.target as HTMLElement;
    if (!el || el.id === 'veil-toast') return;

    // Must be a text input
    const isInput = el.tagName === 'TEXTAREA' || el.tagName === 'INPUT'
      || el.getAttribute('contenteditable') !== null;
    if (!isInput) return;

    const selector = generateSelector(el);
    const hostname = window.location.hostname;

    chrome.storage.local.set({ [`veil_input_selector_${hostname}`]: selector }, () => {
      document.removeEventListener('input', onboardingInputHandler, true);
      onboardingMode = 'send';
      showToast('Now click the send button...', 'info');
      document.addEventListener('click', onboardingSendHandler, true);
    });
  }

  function onboardingSendHandler(e: MouseEvent): void {
    if (onboardingMode !== 'send') return;

    const el = e.target as HTMLElement;
    // Skip if clicking inside our own UI
    const toast = document.getElementById('veil-toast');
    if (toast && toast.contains(el)) return;

    e.preventDefault();
    e.stopPropagation();

    const selector = generateSelector(el);
    const hostname = window.location.hostname;

    chrome.storage.local.set({ [`veil_send_selector_${hostname}`]: selector }, () => {
      document.removeEventListener('click', onboardingSendHandler, true);
      onboardingMode = null;
      showToast('Setup complete!', 'success');
    });
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

  // ---------------------------------------------------------------------------
  // Toast notifications (replaces sidebar feedback)
  // ---------------------------------------------------------------------------

  function showToast(message: string, type: 'info' | 'success' | 'danger' = 'info'): void {
    let toast = document.getElementById('veil-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'veil-toast';
      const style = document.createElement('style');
      style.textContent = `
        #veil-toast {
          position: fixed;
          top: 16px;
          left: 50%;
          transform: translateX(-50%);
          z-index: 2147483647;
          padding: 10px 20px;
          border-radius: 8px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          font-size: 14px;
          font-weight: 500;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          transition: opacity 0.3s;
          pointer-events: none;
        }
        #veil-toast.info { background: #1a1a2e; color: #e0e0e8; border: 1px solid #6c63ff; }
        #veil-toast.success { background: #1a2e1a; color: #2ed573; border: 1px solid #2ed573; }
        #veil-toast.danger { background: #2e1a1a; color: #ff4757; border: 1px solid #ff4757; }
      `;
      document.head.appendChild(style);
      document.body.appendChild(toast);
    }

    toast.textContent = message;
    toast.className = type;
    toast.style.opacity = '1';

    // Auto-hide after 3s (except during onboarding)
    if (type !== 'info' || !onboardingMode) {
      setTimeout(() => {
        if (toast) toast.style.opacity = '0';
        setTimeout(() => toast?.remove(), 300);
      }, 3000);
    }
  }

  // ---------------------------------------------------------------------------
  // Message routing: background ↔ popup → content
  // ---------------------------------------------------------------------------

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    switch (message.type) {
      case 'START_SESSION':
        startSession();
        sendResponse({ ok: true });
        break;
      case 'END_SESSION':
        endSession();
        sendResponse({ ok: true });
        break;
      case 'START_ONBOARDING':
        startOnboarding();
        sendResponse({ ok: true });
        break;
      case 'GET_SESSION_STATE':
        sendResponse({
          handshakeState,
          fingerprint,
          myPublicKeyBase64,
          theirPublicKeyBase64,
          inBandVerify,
          serverVerify,
          serverVerifyError,
        });
        break;
      case 'DEBUG_SCAN':
        // Force a re-scan of existing DOM nodes (for testing)
        scanExistingNodes();
        sendResponse({ ok: true, state: handshakeState, myNonce });
        break;
      case 'DEBUG_GET_LAST_ENCRYPTED':
        sendResponse({ encrypted: lastEncryptedOutgoing });
        lastEncryptedOutgoing = null;
        break;
    }
  });

  // ---------------------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------------------

  async function init(): Promise<void> {
    // NOTE: Do NOT call restoreSession() here. chrome.storage.session is shared
    // across ALL tabs in the extension. If Tab A saves its session, Tab B would
    // restore Tab A's keys and think Tab A's invite is its own — breaking the
    // handshake. Session state is per-tab (in-memory only).
    startObserver();
  }

  init();
})();
