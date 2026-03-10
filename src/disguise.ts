// Veil — Ciphertext disguise layer (v2: visible bracket tags)
// Tags are reliable across all messengers and trivial to find in the DOM.

import type { HandshakeData } from './types';

// Tag format: [VL:X]payload[/VL]
// X = E (encrypted message), H (handshake), V (verify fingerprint)
const TAG_E_OPEN  = '[VL:E]';
const TAG_H_OPEN  = '[VL:H]';
const TAG_V_OPEN  = '[VL:V]';
const TAG_CLOSE   = '[/VL]';

// Detects any Veil message without knowing the type
function isAnyVeil(text: string): boolean {
  return text.includes('[VL:');
}

// --- Encrypted message ---

function wrapMessage(base64Ciphertext: string): string {
  return `${TAG_E_OPEN}${base64Ciphertext}${TAG_CLOSE}`;
}

function unwrapMessage(text: string): string | null {
  const start = text.indexOf(TAG_E_OPEN);
  if (start === -1) return null;
  const payloadStart = start + TAG_E_OPEN.length;
  const end = text.indexOf(TAG_CLOSE, payloadStart);
  if (end === -1) return null;
  return text.slice(payloadStart, end);
}

function isVeilMessage(text: string): boolean {
  return text.includes(TAG_E_OPEN);
}

// --- Handshake ---

function wrapHandshake(publicKeyBase64: string, signatureBase64: string): string {
  return `${TAG_H_OPEN}${publicKeyBase64}.${signatureBase64}${TAG_CLOSE}`;
}

function unwrapHandshake(text: string): HandshakeData | null {
  const start = text.indexOf(TAG_H_OPEN);
  if (start === -1) return null;
  const payloadStart = start + TAG_H_OPEN.length;
  const end = text.indexOf(TAG_CLOSE, payloadStart);
  if (end === -1) return null;
  const payload = text.slice(payloadStart, end);
  const dot = payload.indexOf('.');
  if (dot === -1) return null;
  return { publicKey: payload.slice(0, dot), signature: payload.slice(dot + 1) };
}

function isHandshake(text: string): boolean {
  return text.includes(TAG_H_OPEN);
}

// --- Fingerprint verification ---

function wrapVerify(encryptedFingerprint: string): string {
  return `${TAG_V_OPEN}${encryptedFingerprint}${TAG_CLOSE}`;
}

function unwrapVerify(text: string): string | null {
  const start = text.indexOf(TAG_V_OPEN);
  if (start === -1) return null;
  const payloadStart = start + TAG_V_OPEN.length;
  const end = text.indexOf(TAG_CLOSE, payloadStart);
  if (end === -1) return null;
  return text.slice(payloadStart, end);
}

function isVerifyMessage(text: string): boolean {
  return text.includes(TAG_V_OPEN);
}

export const VeilDisguise = {
  isAnyVeil,
  wrapMessage,
  unwrapMessage,
  isVeilMessage,
  wrapHandshake,
  unwrapHandshake,
  isHandshake,
  wrapVerify,
  unwrapVerify,
  isVerifyMessage,
  TAG_E_OPEN,
  TAG_H_OPEN,
  TAG_V_OPEN,
  TAG_CLOSE,
};
