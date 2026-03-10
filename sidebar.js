"use strict";
(() => {
  // src/crypto.ts
  var IV_LENGTH = 12;
  var TAG_LENGTH = 128;
  var PROVENANCE_KEY_RAW = new Uint8Array([
    86,
    69,
    73,
    76,
    45,
    80,
    82,
    79,
    86,
    69,
    78,
    65,
    78,
    67,
    69,
    45,
    75,
    69,
    89,
    45,
    50,
    48,
    50,
    54,
    45,
    86,
    49,
    45,
    83,
    69,
    67,
    82
  ]);
  async function generateKeyPair() {
    return await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );
  }
  async function exportPublicKey(keyPair) {
    const raw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    return arrayBufferToBase64(raw);
  }
  async function importPublicKey(base64) {
    const raw = base64ToArrayBuffer(base64);
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  }
  async function exportPrivateKey(keyPair) {
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return JSON.stringify(jwk);
  }
  async function importPrivateKey(jwkString) {
    const jwk = JSON.parse(jwkString);
    return await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );
  }
  async function deriveSharedKey(privateKey, publicKey) {
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: publicKey },
      privateKey,
      256
    );
    const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new TextEncoder().encode("veil-v1-salt"),
        info: new TextEncoder().encode("veil-v1-aes-key")
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  async function encrypt(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: TAG_LENGTH },
      aesKey,
      encoded
    );
    const result = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertext), IV_LENGTH);
    return arrayBufferToBase64(result.buffer);
  }
  async function decrypt(aesKey, base64Payload) {
    const data = new Uint8Array(base64ToArrayBuffer(base64Payload));
    const iv = data.slice(0, IV_LENGTH);
    const ciphertext = data.slice(IV_LENGTH);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: TAG_LENGTH },
      aesKey,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }
  async function computeFingerprint(myPublicKeyBase64, theirPublicKeyBase64) {
    const combined = myPublicKeyBase64 + ":" + theirPublicKeyBase64;
    const encoded = new TextEncoder().encode(combined);
    const hash = await crypto.subtle.digest("SHA-256", encoded);
    const bytes = new Uint8Array(hash);
    return Array.from(bytes.slice(0, 4)).map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join("-");
  }
  async function getProvenanceKey() {
    return await crypto.subtle.importKey(
      "raw",
      PROVENANCE_KEY_RAW,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  }
  async function signProvenance(publicKeyBase64) {
    const key = await getProvenanceKey();
    const data = new TextEncoder().encode(publicKeyBase64);
    const sig = await crypto.subtle.sign("HMAC", key, data);
    return arrayBufferToBase64(sig);
  }
  async function verifyProvenance(publicKeyBase64, signatureBase64) {
    const key = await getProvenanceKey();
    const data = new TextEncoder().encode(publicKeyBase64);
    const sig = base64ToArrayBuffer(signatureBase64);
    return await crypto.subtle.verify("HMAC", key, sig, data);
  }
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
  var VeilCrypto = {
    generateKeyPair,
    exportPublicKey,
    importPublicKey,
    exportPrivateKey,
    importPrivateKey,
    deriveSharedKey,
    encrypt,
    decrypt,
    computeFingerprint,
    signProvenance,
    verifyProvenance,
    arrayBufferToBase64,
    base64ToArrayBuffer
  };

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

  // src/i18n.ts
  var STRINGS = {
    en: {
      app_name: "VEIL",
      start_session: "Start Secure Session",
      complete_handshake: "Complete Handshake",
      waiting: "Waiting for reply...",
      verified: "Session Verified",
      no_session: "No active secure session.",
      send_encrypted: "Send Encrypted",
      end_session: "End Session",
      settings: "Settings",
      copy: "Copy",
      copied: "Copied!",
      cancel: "Cancel",
      type_message: "Type your message...",
      send_invite: "Send this to your contact:",
      copy_invite: "Copy Invite Code",
      waiting_reply: "Waiting for their reply...",
      manual_tools: "Manual Tools",
      paste_decrypt: "Paste ciphertext to decrypt",
      decrypt: "Decrypt",
      onboarding_input: "To auto-send encrypted messages, click your chat input box now.",
      onboarding_send: "Now click the Send button.",
      onboarding_done: "Setup complete! Auto-send is configured for this site.",
      onboarding_reset: "Re-configure input detection",
      language: "Language",
      secure: "Secure",
      fingerprint: "Fingerprint",
      fingerprint_match: "Fingerprint verified - session is secure.",
      fingerprint_mismatch: "WARNING: Fingerprint mismatch! Possible MITM attack. Do NOT proceed.",
      compare_fingerprint: "Compare this fingerprint with your contact via a separate channel:",
      you: "You",
      them: "Them",
      session_ended: "Session ended. Keys wiped.",
      copy_fallback: "Could not auto-send. Copy and paste manually:",
      what_veil_does: "Veil encrypts your messages before they leave your browser. The messenger platform only sees encrypted text.",
      what_veil_cannot: "Veil cannot protect against device-level compromise (malware, spyware, keyloggers), physical access to an unlocked device, or metadata (who you talk to, when, how often).",
      hygiene_note: "Close your browser when you are not actively chatting. While the browser is open, session keys exist in RAM.",
      first_launch_welcome: "Welcome to Veil",
      choose_language: "Choose your language",
      handshake_received: "Handshake invite detected. Complete the handshake?",
      accept_handshake: "Accept & Connect",
      step1_title: "Step 1: Create invite",
      step1_desc: "Click below to generate a secure invite code. Send this code to your contact through the chat.",
      step2_title: "Step 2: Wait for response",
      step2_desc: 'Your contact must open Veil, click "I Received an Invite", and paste your code. They will send back their own code.',
      step3_title: "Step 3: Connected!",
      step3_desc: "Both sides verified. You can now send encrypted messages.",
      create_invite: "Create Invite",
      i_received_invite: "I Received an Invite",
      paste_invite_prompt: "Paste the invite code you received from your contact:",
      paste_here: "Paste invite code here...",
      connect: "Connect",
      status_generating: "Generating secure keys...",
      status_connected: "Connected & Verified",
      status_waiting: "Waiting for contact's response...",
      how_it_works: "How it works",
      how_it_works_desc: "1. One person creates an invite and sends the code\n2. The other person pastes the code and connects\n3. Both sides are now encrypted end-to-end",
      or_paste_reply: "Or paste the reply code manually:",
      paste_reply_here: "Paste reply code here...",
      submit_reply: "Submit Reply",
      paste_incoming: "Paste incoming message to decrypt:",
      paste_incoming_here: "Paste encrypted message here...",
      decrypt_incoming: "Decrypt"
    },
    fa: {
      app_name: "VEIL",
      start_session: "\u0634\u0631\u0648\u0639 \u06AF\u0641\u062A\u06AF\u0648\u06CC \u0627\u0645\u0646",
      complete_handshake: "\u062A\u06A9\u0645\u06CC\u0644 \u062F\u0633\u062A\u200C\u062F\u0627\u062F",
      waiting: "\u062F\u0631 \u0627\u0646\u062A\u0638\u0627\u0631 \u067E\u0627\u0633\u062E...",
      verified: "\u062C\u0644\u0633\u0647 \u062A\u0623\u06CC\u06CC\u062F \u0634\u062F",
      no_session: "\u0647\u06CC\u0686 \u062C\u0644\u0633\u0647 \u0627\u0645\u0646\u06CC \u0641\u0639\u0627\u0644 \u0646\u06CC\u0633\u062A.",
      send_encrypted: "\u0627\u0631\u0633\u0627\u0644 \u0631\u0645\u0632\u06AF\u0630\u0627\u0631\u06CC \u0634\u062F\u0647",
      end_session: "\u067E\u0627\u06CC\u0627\u0646 \u062C\u0644\u0633\u0647",
      settings: "\u062A\u0646\u0638\u06CC\u0645\u0627\u062A",
      copy: "\u06A9\u067E\u06CC",
      copied: "\u06A9\u067E\u06CC \u0634\u062F!",
      cancel: "\u0644\u063A\u0648",
      type_message: "\u067E\u06CC\u0627\u0645 \u062E\u0648\u062F \u0631\u0627 \u0628\u0646\u0648\u06CC\u0633\u06CC\u062F...",
      send_invite: "\u0627\u06CC\u0646 \u0631\u0627 \u0628\u0631\u0627\u06CC \u0645\u062E\u0627\u0637\u0628 \u062E\u0648\u062F \u0627\u0631\u0633\u0627\u0644 \u06A9\u0646\u06CC\u062F:",
      copy_invite: "\u06A9\u067E\u06CC \u06A9\u062F \u062F\u0639\u0648\u062A",
      waiting_reply: "\u062F\u0631 \u0627\u0646\u062A\u0638\u0627\u0631 \u067E\u0627\u0633\u062E \u0622\u0646\u200C\u0647\u0627...",
      manual_tools: "\u0627\u0628\u0632\u0627\u0631\u0647\u0627\u06CC \u062F\u0633\u062A\u06CC",
      paste_decrypt: "\u0645\u062A\u0646 \u0631\u0645\u0632\u06AF\u0630\u0627\u0631\u06CC \u0634\u062F\u0647 \u0631\u0627 \u0628\u0631\u0627\u06CC \u0631\u0645\u0632\u06AF\u0634\u0627\u06CC\u06CC \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F",
      decrypt: "\u0631\u0645\u0632\u06AF\u0634\u0627\u06CC\u06CC",
      onboarding_input: "\u0628\u0631\u0627\u06CC \u0627\u0631\u0633\u0627\u0644 \u062E\u0648\u062F\u06A9\u0627\u0631\u060C \u0631\u0648\u06CC \u06A9\u0627\u062F\u0631 \u0648\u0631\u0648\u062F\u06CC \u067E\u06CC\u0627\u0645 \u06A9\u0644\u06CC\u06A9 \u06A9\u0646\u06CC\u062F.",
      onboarding_send: "\u062D\u0627\u0644\u0627 \u0631\u0648\u06CC \u062F\u06A9\u0645\u0647 \u0627\u0631\u0633\u0627\u0644 \u06A9\u0644\u06CC\u06A9 \u06A9\u0646\u06CC\u062F.",
      onboarding_done: "\u062A\u0646\u0638\u06CC\u0645\u0627\u062A \u06A9\u0627\u0645\u0644 \u0634\u062F! \u0627\u0631\u0633\u0627\u0644 \u062E\u0648\u062F\u06A9\u0627\u0631 \u0628\u0631\u0627\u06CC \u0627\u06CC\u0646 \u0633\u0627\u06CC\u062A \u067E\u06CC\u06A9\u0631\u0628\u0646\u062F\u06CC \u0634\u062F.",
      onboarding_reset: "\u067E\u06CC\u06A9\u0631\u0628\u0646\u062F\u06CC \u0645\u062C\u062F\u062F \u062A\u0634\u062E\u06CC\u0635 \u0648\u0631\u0648\u062F\u06CC",
      language: "\u0632\u0628\u0627\u0646",
      secure: "\u0627\u0645\u0646",
      fingerprint: "\u0627\u062B\u0631 \u0627\u0646\u06AF\u0634\u062A",
      fingerprint_match: "\u0627\u062B\u0631 \u0627\u0646\u06AF\u0634\u062A \u062A\u0623\u06CC\u06CC\u062F \u0634\u062F - \u062C\u0644\u0633\u0647 \u0627\u0645\u0646 \u0627\u0633\u062A.",
      fingerprint_mismatch: "\u0647\u0634\u062F\u0627\u0631: \u0639\u062F\u0645 \u062A\u0637\u0627\u0628\u0642 \u0627\u062B\u0631 \u0627\u0646\u06AF\u0634\u062A! \u062D\u0645\u0644\u0647 MITM \u0645\u0645\u06A9\u0646 \u0627\u0633\u062A. \u0627\u062F\u0627\u0645\u0647 \u0646\u062F\u0647\u06CC\u062F.",
      compare_fingerprint: "\u0627\u06CC\u0646 \u0627\u062B\u0631 \u0627\u0646\u06AF\u0634\u062A \u0631\u0627 \u0627\u0632 \u06A9\u0627\u0646\u0627\u0644 \u062F\u06CC\u06AF\u0631\u06CC \u0628\u0627 \u0645\u062E\u0627\u0637\u0628 \u0645\u0642\u0627\u06CC\u0633\u0647 \u06A9\u0646\u06CC\u062F:",
      you: "\u0634\u0645\u0627",
      them: "\u0622\u0646\u200C\u0647\u0627",
      session_ended: "\u062C\u0644\u0633\u0647 \u067E\u0627\u06CC\u0627\u0646 \u06CC\u0627\u0641\u062A. \u06A9\u0644\u06CC\u062F\u0647\u0627 \u067E\u0627\u06A9 \u0634\u062F\u0646\u062F.",
      copy_fallback: "\u0627\u0631\u0633\u0627\u0644 \u062E\u0648\u062F\u06A9\u0627\u0631 \u0645\u0645\u06A9\u0646 \u0646\u0634\u062F. \u06A9\u067E\u06CC \u06A9\u0631\u062F\u0647 \u0648 \u062F\u0633\u062A\u06CC \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F:",
      what_veil_does: "Veil \u067E\u06CC\u0627\u0645\u200C\u0647\u0627\u06CC \u0634\u0645\u0627 \u0631\u0627 \u0642\u0628\u0644 \u0627\u0632 \u062E\u0631\u0648\u062C \u0627\u0632 \u0645\u0631\u0648\u0631\u06AF\u0631 \u0631\u0645\u0632\u06AF\u0630\u0627\u0631\u06CC \u0645\u06CC\u200C\u06A9\u0646\u062F. \u067E\u0644\u062A\u0641\u0631\u0645 \u067E\u06CC\u0627\u0645\u200C\u0631\u0633\u0627\u0646 \u0641\u0642\u0637 \u0645\u062A\u0646 \u0631\u0645\u0632\u06AF\u0630\u0627\u0631\u06CC \u0634\u062F\u0647 \u0631\u0627 \u0645\u06CC\u200C\u0628\u06CC\u0646\u062F.",
      what_veil_cannot: "Veil \u0646\u0645\u06CC\u200C\u062A\u0648\u0627\u0646\u062F \u062F\u0631 \u0628\u0631\u0627\u0628\u0631 \u0622\u0644\u0648\u062F\u06AF\u06CC \u062F\u0633\u062A\u06AF\u0627\u0647 (\u0628\u062F\u0627\u0641\u0632\u0627\u0631\u060C \u062C\u0627\u0633\u0648\u0633\u200C\u0627\u0641\u0632\u0627\u0631\u060C \u06A9\u06CC\u200C\u0644\u0627\u06AF\u0631)\u060C \u062F\u0633\u062A\u0631\u0633\u06CC \u0641\u06CC\u0632\u06CC\u06A9\u06CC \u0628\u0647 \u062F\u0633\u062A\u06AF\u0627\u0647 \u0628\u0627\u0632\u060C \u06CC\u0627 \u0641\u0631\u0627\u062F\u0627\u062F\u0647 (\u0628\u0627 \u06A9\u06CC \u0635\u062D\u0628\u062A \u0645\u06CC\u200C\u06A9\u0646\u06CC\u062F\u060C \u06A9\u06CC\u060C \u0686\u0642\u062F\u0631) \u0645\u062D\u0627\u0641\u0638\u062A \u06A9\u0646\u062F.",
      hygiene_note: "\u0648\u0642\u062A\u06CC \u0686\u062A \u0646\u0645\u06CC\u200C\u06A9\u0646\u06CC\u062F \u0645\u0631\u0648\u0631\u06AF\u0631 \u0631\u0627 \u0628\u0628\u0646\u062F\u06CC\u062F. \u062A\u0627 \u0632\u0645\u0627\u0646\u06CC \u06A9\u0647 \u0645\u0631\u0648\u0631\u06AF\u0631 \u0628\u0627\u0632 \u0627\u0633\u062A\u060C \u06A9\u0644\u06CC\u062F\u0647\u0627\u06CC \u062C\u0644\u0633\u0647 \u062F\u0631 \u062D\u0627\u0641\u0638\u0647 \u0648\u062C\u0648\u062F \u062F\u0627\u0631\u0646\u062F.",
      first_launch_welcome: "\u0628\u0647 Veil \u062E\u0648\u0634 \u0622\u0645\u062F\u06CC\u062F",
      choose_language: "\u0632\u0628\u0627\u0646 \u062E\u0648\u062F \u0631\u0627 \u0627\u0646\u062A\u062E\u0627\u0628 \u06A9\u0646\u06CC\u062F",
      handshake_received: "\u062F\u0639\u0648\u062A \u062F\u0633\u062A\u200C\u062F\u0627\u062F \u0634\u0646\u0627\u0633\u0627\u06CC\u06CC \u0634\u062F. \u062F\u0633\u062A\u200C\u062F\u0627\u062F \u0631\u0627 \u062A\u06A9\u0645\u06CC\u0644 \u0645\u06CC\u200C\u06A9\u0646\u06CC\u062F\u061F",
      accept_handshake: "\u0642\u0628\u0648\u0644 \u0648 \u0627\u062A\u0635\u0627\u0644",
      step1_title: "\u0645\u0631\u062D\u0644\u0647 \u06F1: \u0633\u0627\u062E\u062A \u062F\u0639\u0648\u062A",
      step1_desc: "\u0628\u0631\u0627\u06CC \u0633\u0627\u062E\u062A \u06A9\u062F \u062F\u0639\u0648\u062A \u0627\u0645\u0646 \u06A9\u0644\u06CC\u06A9 \u06A9\u0646\u06CC\u062F. \u0627\u06CC\u0646 \u06A9\u062F \u0631\u0627 \u0627\u0632 \u0637\u0631\u06CC\u0642 \u0686\u062A \u0628\u0631\u0627\u06CC \u0645\u062E\u0627\u0637\u0628 \u062E\u0648\u062F \u0627\u0631\u0633\u0627\u0644 \u06A9\u0646\u06CC\u062F.",
      step2_title: "\u0645\u0631\u062D\u0644\u0647 \u06F2: \u0627\u0646\u062A\u0638\u0627\u0631 \u067E\u0627\u0633\u062E",
      step2_desc: "\u0645\u062E\u0627\u0637\u0628 \u0634\u0645\u0627 \u0628\u0627\u06CC\u062F Veil \u0631\u0627 \u0628\u0627\u0632 \u06A9\u0646\u062F\u060C \xAB\u06A9\u062F \u062F\u0639\u0648\u062A \u062F\u0631\u06CC\u0627\u0641\u062A \u06A9\u0631\u062F\u0645\xBB \u0631\u0627 \u0628\u0632\u0646\u062F \u0648 \u06A9\u062F \u0634\u0645\u0627 \u0631\u0627 \u0628\u0686\u0633\u0628\u0627\u0646\u062F.",
      step3_title: "\u0645\u0631\u062D\u0644\u0647 \u06F3: \u0645\u062A\u0635\u0644 \u0634\u062F!",
      step3_desc: "\u0647\u0631 \u062F\u0648 \u0637\u0631\u0641 \u062A\u0623\u06CC\u06CC\u062F \u0634\u062F\u0646\u062F. \u0627\u06A9\u0646\u0648\u0646 \u0645\u06CC\u200C\u062A\u0648\u0627\u0646\u06CC\u062F \u067E\u06CC\u0627\u0645 \u0631\u0645\u0632\u06AF\u0630\u0627\u0631\u06CC \u0634\u062F\u0647 \u0627\u0631\u0633\u0627\u0644 \u06A9\u0646\u06CC\u062F.",
      create_invite: "\u0633\u0627\u062E\u062A \u062F\u0639\u0648\u062A",
      i_received_invite: "\u06A9\u062F \u062F\u0639\u0648\u062A \u062F\u0631\u06CC\u0627\u0641\u062A \u06A9\u0631\u062F\u0645",
      paste_invite_prompt: "\u06A9\u062F \u062F\u0639\u0648\u062A\u06CC \u06A9\u0647 \u0627\u0632 \u0645\u062E\u0627\u0637\u0628 \u062F\u0631\u06CC\u0627\u0641\u062A \u06A9\u0631\u062F\u06CC\u062F \u0631\u0627 \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F:",
      paste_here: "\u06A9\u062F \u062F\u0639\u0648\u062A \u0631\u0627 \u0627\u06CC\u0646\u062C\u0627 \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F...",
      connect: "\u0627\u062A\u0635\u0627\u0644",
      status_generating: "\u062F\u0631 \u062D\u0627\u0644 \u0633\u0627\u062E\u062A \u06A9\u0644\u06CC\u062F\u0647\u0627\u06CC \u0627\u0645\u0646...",
      status_connected: "\u0645\u062A\u0635\u0644 \u0648 \u062A\u0623\u06CC\u06CC\u062F \u0634\u062F\u0647",
      status_waiting: "\u062F\u0631 \u0627\u0646\u062A\u0638\u0627\u0631 \u067E\u0627\u0633\u062E \u0645\u062E\u0627\u0637\u0628...",
      how_it_works: "\u0646\u062D\u0648\u0647 \u06A9\u0627\u0631",
      how_it_works_desc: "\u06F1. \u06CC\u06A9 \u0646\u0641\u0631 \u062F\u0639\u0648\u062A \u0645\u06CC\u200C\u0633\u0627\u0632\u062F \u0648 \u06A9\u062F \u0631\u0627 \u0627\u0631\u0633\u0627\u0644 \u0645\u06CC\u200C\u06A9\u0646\u062F\n\u06F2. \u0646\u0641\u0631 \u062F\u06CC\u06AF\u0631 \u06A9\u062F \u0631\u0627 \u0645\u06CC\u200C\u0686\u0633\u0628\u0627\u0646\u062F \u0648 \u0645\u062A\u0635\u0644 \u0645\u06CC\u200C\u0634\u0648\u062F\n\u06F3. \u0647\u0631 \u062F\u0648 \u0637\u0631\u0641 \u0631\u0645\u0632\u06AF\u0630\u0627\u0631\u06CC \u0633\u0631\u062A\u0627\u0633\u0631\u06CC \u062F\u0627\u0631\u0646\u062F",
      or_paste_reply: "\u06CC\u0627 \u06A9\u062F \u067E\u0627\u0633\u062E \u0631\u0627 \u062F\u0633\u062A\u06CC \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F:",
      paste_reply_here: "\u06A9\u062F \u067E\u0627\u0633\u062E \u0631\u0627 \u0627\u06CC\u0646\u062C\u0627 \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F...",
      submit_reply: "\u062B\u0628\u062A \u067E\u0627\u0633\u062E",
      paste_incoming: "\u067E\u06CC\u0627\u0645 \u062F\u0631\u06CC\u0627\u0641\u062A\u06CC \u0631\u0627 \u0628\u0631\u0627\u06CC \u0631\u0645\u0632\u06AF\u0634\u0627\u06CC\u06CC \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F:",
      paste_incoming_here: "\u067E\u06CC\u0627\u0645 \u0631\u0645\u0632\u06AF\u0630\u0627\u0631\u06CC \u0634\u062F\u0647 \u0631\u0627 \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F...",
      decrypt_incoming: "\u0631\u0645\u0632\u06AF\u0634\u0627\u06CC\u06CC"
    }
  };
  var _veilLang = "en";
  function t(key) {
    return STRINGS[_veilLang] && STRINGS[_veilLang][key] || STRINGS.en[key] || key;
  }
  function setLang(lang) {
    _veilLang = lang;
  }
  function getLang() {
    return _veilLang;
  }

  // src/sidebar.ts
  (() => {
    let currentPanel = null;
    let previousPanel = null;
    let sessionKey = null;
    let myKeyPair = null;
    let myPublicKeyBase64 = null;
    let theirPublicKeyBase64 = null;
    let fingerprint = null;
    let verified = false;
    let messages = [];
    let pendingReplyCode = null;
    async function init() {
      chrome.storage.local.get(["veil_lang"], (data) => {
        if (data.veil_lang) {
          setLang(data.veil_lang);
          applyLanguage();
          showPanel("panelNoSession");
        } else {
          showPanel("panelLang");
        }
      });
      bindEvents();
    }
    function applyLanguage() {
      const lang = getLang();
      const dir = lang === "fa" ? "rtl" : "ltr";
      document.documentElement.dir = dir;
      document.documentElement.lang = lang === "fa" ? "fa" : "en";
      document.querySelectorAll("[data-i18n]").forEach((el) => {
        const key = el.getAttribute("data-i18n");
        if (key) el.textContent = t(key);
      });
      document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
        const key = el.getAttribute("data-i18n-placeholder");
        if (key) el.placeholder = t(key);
      });
    }
    function setLanguage(lang) {
      setLang(lang);
      chrome.storage.local.set({ veil_lang: lang });
      applyLanguage();
    }
    function showPanel(id) {
      if (currentPanel && currentPanel !== id) {
        previousPanel = currentPanel;
      }
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      const panel = document.getElementById(id);
      if (panel) {
        panel.classList.add("active");
        currentPanel = id;
      }
      updateHeader();
    }
    function updateHeader() {
      const status = document.getElementById("headerStatus");
      if (currentPanel === "panelSession" && verified) {
        status.textContent = t("verified") + " \u2713";
        status.className = "header-status verified";
      } else if (currentPanel === "panelSession" && !verified) {
        status.textContent = t("waiting");
        status.className = "header-status warning";
      } else if (currentPanel === "panelHandshake") {
        status.textContent = t("waiting");
        status.className = "header-status";
      } else {
        status.textContent = "";
        status.className = "header-status";
      }
    }
    function bindEvents() {
      document.querySelectorAll(".lang-btn[data-lang]").forEach((btn) => {
        btn.addEventListener("click", () => {
          setLanguage(btn.dataset.lang);
          showPanel("panelNoSession");
        });
      });
      document.getElementById("btnStartSession").addEventListener("click", startSession);
      document.getElementById("btnCompleteHandshake").addEventListener("click", () => {
        showPanel("panelHandshakeReceived");
      });
      document.getElementById("btnCopyInvite").addEventListener("click", () => {
        const code = document.getElementById("inviteCode").textContent ?? "";
        copyToClipboard(code);
        showCopyFeedback("copyFeedback");
      });
      document.getElementById("btnCancelHandshake").addEventListener("click", () => {
        resetSession();
        showPanel("panelNoSession");
      });
      document.getElementById("btnAcceptHandshake").addEventListener("click", acceptHandshake);
      document.getElementById("btnSubmitReply").addEventListener("click", submitReply);
      document.getElementById("btnRejectHandshake").addEventListener("click", () => {
        showPanel("panelNoSession");
      });
      document.getElementById("btnSend").addEventListener("click", sendMessage);
      document.getElementById("composeInput").addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          sendMessage();
        }
      });
      document.getElementById("btnDecryptIncoming").addEventListener("click", decryptIncomingManual);
      document.getElementById("btnEndSession").addEventListener("click", () => {
        resetSession();
        addSystemMessage(t("session_ended"));
        showPanel("panelNoSession");
      });
      document.getElementById("btnSettings").addEventListener("click", () => showPanel("panelSettings"));
      document.getElementById("btnSessionSettings").addEventListener("click", () => showPanel("panelSettings"));
      document.getElementById("btnBackFromSettings").addEventListener("click", () => {
        showPanel(previousPanel ?? (sessionKey ? "panelSession" : "panelNoSession"));
      });
      document.getElementById("btnResetOnboarding").addEventListener("click", startOnboardingFlow);
      document.getElementById("btnManualDecrypt").addEventListener("click", manualDecrypt);
      document.getElementById("btnCopyFallback").addEventListener("click", () => {
        const text = document.getElementById("fallbackText").textContent ?? "";
        copyToClipboard(text);
        showCopyFeedback("copyFallbackFeedback");
      });
      document.getElementById("btnBackFromFallback").addEventListener("click", () => {
        showPanel("panelSession");
      });
      document.getElementById("btnSkipOnboarding").addEventListener("click", () => {
        showPanel(sessionKey ? "panelSession" : "panelNoSession");
      });
      window.addEventListener("message", handleContentMessage);
    }
    async function startSession() {
      try {
        myKeyPair = await VeilCrypto.generateKeyPair();
        myPublicKeyBase64 = await VeilCrypto.exportPublicKey(myKeyPair);
        const signature = await VeilCrypto.signProvenance(myPublicKeyBase64);
        const inviteWrapped = VeilDisguise.wrapHandshake(myPublicKeyBase64, signature);
        const inviteRaw = myPublicKeyBase64 + "." + signature;
        document.getElementById("inviteCode").textContent = inviteRaw;
        showPanel("panelHandshake");
        sendToContent({ type: "INJECT_TEXT", text: inviteWrapped });
        const privKeyExport = await VeilCrypto.exportPrivateKey(myKeyPair);
        chrome.storage.session.set({
          veil_private_key: privKeyExport,
          veil_public_key: myPublicKeyBase64,
          veil_role: "initiator"
        });
      } catch (err) {
        console.error("Veil: startSession error", err);
      }
    }
    async function acceptHandshake() {
      const errorEl = document.getElementById("handshakeError");
      errorEl.style.display = "none";
      const pasteInput = document.getElementById("pasteInviteInput");
      const rawInput = pasteInput.value.trim();
      if (!rawInput) return;
      let handshakeData = VeilDisguise.unwrapHandshake(rawInput);
      if (!handshakeData) {
        const cleaned = rawInput.replace(/[\u200B\u200C\u200D\uFEFF]/g, "").trim();
        const dotIdx = cleaned.indexOf(".");
        if (dotIdx > 0 && dotIdx < cleaned.length - 1) {
          handshakeData = {
            publicKey: cleaned.slice(0, dotIdx),
            signature: cleaned.slice(dotIdx + 1)
          };
        }
      }
      if (!handshakeData) {
        errorEl.textContent = "Invalid invite code. Make sure you copied the full code.";
        errorEl.style.display = "block";
        return;
      }
      const valid = await VeilCrypto.verifyProvenance(handshakeData.publicKey, handshakeData.signature);
      if (!valid) {
        errorEl.textContent = "Invalid invite code. This does not appear to be from Veil.";
        errorEl.style.display = "block";
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
          veil_role: "responder"
        });
        document.getElementById("fingerprintValue").textContent = fingerprint;
        document.getElementById("fingerprintSection").style.display = "block";
        addSystemMessage(t("step3_desc"));
        pendingReplyCode = combinedReply;
        showPanel("panelSession");
        sendToContent({ type: "INJECT_TEXT", text: combinedReply });
      } catch (err) {
        console.error("Veil: acceptHandshake error", err);
      }
    }
    async function submitReply() {
      const input = document.getElementById("pasteReplyInput");
      const errorEl = document.getElementById("replyError");
      const rawInput = input.value.trim();
      if (!rawInput || !myKeyPair) return;
      errorEl.style.display = "none";
      let handshakeData = VeilDisguise.unwrapHandshake(rawInput);
      if (!handshakeData) {
        const cleaned = rawInput.replace(/[\u200B\u200C\u200D\uFEFF]/g, "").trim();
        const dotIdx = cleaned.indexOf(".");
        if (dotIdx > 0 && dotIdx < cleaned.length - 1) {
          handshakeData = {
            publicKey: cleaned.slice(0, dotIdx),
            signature: cleaned.slice(dotIdx + 1)
          };
        }
      }
      if (!handshakeData) {
        errorEl.textContent = "Invalid reply code.";
        errorEl.style.display = "block";
        return;
      }
      await completeHandshakeAsInitiator(handshakeData.publicKey);
    }
    async function completeHandshakeAsInitiator(theirPubKeyBase64) {
      try {
        const theirKey = await VeilCrypto.importPublicKey(theirPubKeyBase64);
        theirPublicKeyBase64 = theirPubKeyBase64;
        sessionKey = await VeilCrypto.deriveSharedKey(myKeyPair.privateKey, theirKey);
        fingerprint = await VeilCrypto.computeFingerprint(myPublicKeyBase64, theirPubKeyBase64);
        chrome.storage.session.set({ veil_their_public_key: theirPubKeyBase64 });
        document.getElementById("fingerprintValue").textContent = fingerprint;
        document.getElementById("fingerprintSection").style.display = "block";
        showPanel("panelSession");
      } catch (err) {
        console.error("Veil: completeHandshakeAsInitiator error", err);
      }
    }
    async function handleVerifyMessage(encryptedPayload) {
      if (!sessionKey) return;
      try {
        const receivedFingerprint = await VeilCrypto.decrypt(sessionKey, encryptedPayload);
        const expectedFingerprint = await VeilCrypto.computeFingerprint(
          theirPublicKeyBase64,
          myPublicKeyBase64
        );
        if (receivedFingerprint === expectedFingerprint) {
          verified = true;
          addSystemMessage(t("fingerprint_match"));
          const stored = await getSessionStorage("veil_role");
          if (stored === "initiator") {
            const myFp = await VeilCrypto.computeFingerprint(myPublicKeyBase64, theirPublicKeyBase64);
            const verifyPayload = await VeilCrypto.encrypt(sessionKey, myFp);
            const verifyMsg = VeilDisguise.wrapVerify(verifyPayload);
            sendToContent({ type: "INJECT_TEXT", text: verifyMsg });
          }
        } else {
          verified = false;
          addSystemMessage(t("fingerprint_mismatch"));
        }
        updateHeader();
      } catch (err) {
        console.error("Veil: verify error", err);
      }
    }
    function resetSession() {
      sessionKey = null;
      myKeyPair = null;
      myPublicKeyBase64 = null;
      theirPublicKeyBase64 = null;
      fingerprint = null;
      verified = false;
      messages = [];
      renderMessages();
      chrome.storage.session.remove([
        "veil_private_key",
        "veil_public_key",
        "veil_their_public_key",
        "veil_session_key",
        "veil_role"
      ]);
      document.getElementById("fingerprintSection").style.display = "none";
      updateHeader();
    }
    async function sendMessage() {
      const input = document.getElementById("composeInput");
      const plaintext = input.value.trim();
      if (!plaintext || !sessionKey) return;
      try {
        const encrypted = await VeilCrypto.encrypt(sessionKey, plaintext);
        const wrapped = VeilDisguise.wrapMessage(encrypted);
        sendToContent({ type: "INJECT_TEXT", text: wrapped });
        addMessage("you", plaintext);
        input.value = "";
        input.focus();
      } catch (err) {
        console.error("Veil: encrypt error", err);
      }
    }
    async function decryptIncoming(base64Payload) {
      if (!sessionKey) return;
      try {
        const plaintext = await VeilCrypto.decrypt(sessionKey, base64Payload);
        addMessage("them", plaintext);
      } catch (err) {
        console.error("Veil: decrypt error", err);
      }
    }
    async function decryptIncomingManual() {
      const input = document.getElementById("pasteIncomingInput");
      const text = input.value.trim();
      if (!text || !sessionKey) return;
      let payload = text;
      if (VeilDisguise.isVeilMessage(text)) {
        payload = VeilDisguise.unwrapMessage(text) ?? text;
      }
      try {
        const plaintext = await VeilCrypto.decrypt(sessionKey, payload);
        addMessage("them", plaintext);
        input.value = "";
      } catch {
      }
    }
    async function manualDecrypt() {
      const input = document.getElementById("manualDecryptInput");
      const resultEl = document.getElementById("manualDecryptResult");
      const text = input.value.trim();
      if (!text) return;
      let payload = text;
      if (VeilDisguise.isVeilMessage(text)) {
        payload = VeilDisguise.unwrapMessage(text) ?? text;
      }
      if (!sessionKey) {
        resultEl.textContent = "No active session key.";
        return;
      }
      try {
        const plaintext = await VeilCrypto.decrypt(sessionKey, payload);
        resultEl.textContent = plaintext;
        resultEl.style.color = "var(--success)";
      } catch {
        resultEl.textContent = "Decryption failed.";
        resultEl.style.color = "var(--danger)";
      }
    }
    function addMessage(sender, text) {
      messages.push({ sender, text });
      renderMessages();
    }
    function addSystemMessage(text) {
      messages.push({ sender: "system", text });
      renderMessages();
    }
    function renderMessages() {
      const list = document.getElementById("messagesList");
      list.innerHTML = "";
      messages.forEach((msg) => {
        const div = document.createElement("div");
        if (msg.sender === "you") {
          div.className = "msg msg-you";
          div.textContent = msg.text;
        } else if (msg.sender === "them") {
          div.className = "msg msg-them";
          div.textContent = msg.text;
        } else {
          div.className = "msg msg-system";
          div.textContent = msg.text;
        }
        list.appendChild(div);
      });
      list.scrollTop = list.scrollHeight;
    }
    function startOnboardingFlow() {
      showPanel("panelOnboarding");
      document.getElementById("onboardingPrompt").textContent = t("onboarding_input");
      sendToContent({ type: "START_ONBOARDING_INPUT" });
    }
    function sendToContent(msg) {
      window.parent.postMessage({ source: "veil-sidebar", ...msg }, "*");
    }
    function handleContentMessage(e) {
      if (!e.data || e.data.source !== "veil-content") return;
      const msg = e.data;
      switch (msg.type) {
        case "INJECT_FAILED":
          if (currentPanel === "panelHandshake") {
            break;
          }
          if (pendingReplyCode && currentPanel === "panelSession") {
            addSystemMessage(t("copy_fallback"));
            addSystemMessage(pendingReplyCode);
            pendingReplyCode = null;
            break;
          }
          document.getElementById("fallbackText").textContent = msg.text ?? "";
          showPanel("panelCopyFallback");
          break;
        case "INJECT_SUCCESS":
          break;
        case "ONBOARDING_INPUT_SAVED":
          document.getElementById("onboardingPrompt").textContent = t("onboarding_send");
          sendToContent({ type: "START_ONBOARDING_SEND" });
          break;
        case "ONBOARDING_SEND_SAVED":
          document.getElementById("onboardingPrompt").textContent = t("onboarding_done");
          setTimeout(() => {
            showPanel(sessionKey ? "panelSession" : "panelNoSession");
          }, 1500);
          break;
        case "SCANNED_MESSAGES":
          if (msg.messages) handleScannedMessages(msg.messages);
          break;
      }
    }
    async function handleScannedMessages(scannedMessages) {
      for (const msg of scannedMessages) {
        if (msg.type === "handshake") {
          const valid = await VeilCrypto.verifyProvenance(msg.publicKey, msg.signature);
          if (!valid) {
            console.warn("Veil: invalid provenance on handshake");
            continue;
          }
          if (currentPanel === "panelHandshake" && myKeyPair) {
            if (msg.publicKey !== myPublicKeyBase64) {
              await completeHandshakeAsInitiator(msg.publicKey);
            }
          }
        } else if (msg.type === "encrypted") {
          await decryptIncoming(msg.payload);
        } else if (msg.type === "verify") {
          await handleVerifyMessage(msg.payload);
        }
      }
    }
    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).catch(() => {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      });
    }
    function showCopyFeedback(elementId) {
      const el = document.getElementById(elementId);
      el.classList.add("show");
      setTimeout(() => el.classList.remove("show"), 1500);
    }
    function getSessionStorage(key) {
      return new Promise((resolve) => {
        chrome.storage.session.get([key], (data) => {
          resolve(data[key] ?? null);
        });
      });
    }
    init();
  })();
})();
