// Veil — Ciphertext disguise layer (v1: zero-width markers + raw base64)
// v1 uses invisible Unicode markers to identify Veil messages in chat

import type { HandshakeData } from './types';

// Visible prefix for all Veil messages — makes them easy to find in chat DOM
const VEIL_TAG = 'VEIL:';

// Zero-width characters used as prefix/suffix markers
// These are invisible in all messenger UIs
const PREFIX = '\u200B\u200C\u200D\uFEFF'; // ZWS + ZWNJ + ZWJ + BOM
const SUFFIX = '\uFEFF\u200D\u200C\u200B'; // Reversed order

// Handshake markers (different from message markers)
const HANDSHAKE_PREFIX = '\u200C\u200B\u200D\uFEFF';
const HANDSHAKE_SUFFIX = '\uFEFF\u200D\u200B\u200C';

// Verify marker for fingerprint verification messages
const VERIFY_PREFIX = '\u200D\u200C\u200B\uFEFF';
const VERIFY_SUFFIX = '\uFEFF\u200B\u200C\u200D';

function wrapMessage(base64Ciphertext: string): string {
  return VEIL_TAG + PREFIX + base64Ciphertext + SUFFIX;
}

function unwrapMessage(text: string): string | null {
  // Try invisible markers first
  const prefixIdx = text.indexOf(PREFIX);
  if (prefixIdx !== -1) {
    const suffixIdx = text.indexOf(SUFFIX, prefixIdx + PREFIX.length);
    if (suffixIdx !== -1) return text.slice(prefixIdx + PREFIX.length, suffixIdx);
  }
  // Fallback: markers were stripped, look for VEIL: tag with raw base64
  const tagIdx = text.indexOf(VEIL_TAG);
  if (tagIdx !== -1) {
    const after = text.slice(tagIdx + VEIL_TAG.length).replace(/[\u200B\u200C\u200D\uFEFF]/g, '').trim();
    if (after.length > 10) return after;
  }
  return null;
}

function isVeilMessage(text: string): boolean {
  return (text.includes(PREFIX) && text.includes(SUFFIX)) || text.includes(VEIL_TAG);
}

function wrapHandshake(publicKeyBase64: string, signatureBase64: string): string {
  return VEIL_TAG + HANDSHAKE_PREFIX + publicKeyBase64 + '.' + signatureBase64 + HANDSHAKE_SUFFIX;
}

function unwrapHandshake(text: string): HandshakeData | null {
  // Try invisible markers first
  const prefixIdx = text.indexOf(HANDSHAKE_PREFIX);
  if (prefixIdx !== -1) {
    const suffixIdx = text.indexOf(HANDSHAKE_SUFFIX, prefixIdx + HANDSHAKE_PREFIX.length);
    if (suffixIdx !== -1) {
      const payload = text.slice(prefixIdx + HANDSHAKE_PREFIX.length, suffixIdx);
      const dotIdx = payload.indexOf('.');
      if (dotIdx !== -1) {
        return { publicKey: payload.slice(0, dotIdx), signature: payload.slice(dotIdx + 1) };
      }
    }
  }
  // Fallback: markers stripped, try VEIL: tag + raw key.sig
  const tagIdx = text.indexOf(VEIL_TAG);
  if (tagIdx !== -1) {
    const after = text.slice(tagIdx + VEIL_TAG.length).replace(/[\u200B\u200C\u200D\uFEFF]/g, '').trim();
    const dotIdx = after.indexOf('.');
    if (dotIdx > 0 && dotIdx < after.length - 1) {
      return { publicKey: after.slice(0, dotIdx), signature: after.slice(dotIdx + 1) };
    }
  }
  return null;
}

function isHandshake(text: string): boolean {
  return (text.includes(HANDSHAKE_PREFIX) && text.includes(HANDSHAKE_SUFFIX)) || text.includes(VEIL_TAG);
}

function wrapVerify(encryptedFingerprint: string): string {
  return VEIL_TAG + VERIFY_PREFIX + encryptedFingerprint + VERIFY_SUFFIX;
}

function unwrapVerify(text: string): string | null {
  const prefixIdx = text.indexOf(VERIFY_PREFIX);
  if (prefixIdx === -1) return null;
  const suffixIdx = text.indexOf(VERIFY_SUFFIX, prefixIdx + VERIFY_PREFIX.length);
  if (suffixIdx === -1) return null;
  return text.slice(prefixIdx + VERIFY_PREFIX.length, suffixIdx);
}

function isVerifyMessage(text: string): boolean {
  return text.includes(VERIFY_PREFIX) && text.includes(VERIFY_SUFFIX);
}

export const VeilDisguise = {
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
  SUFFIX,
};
