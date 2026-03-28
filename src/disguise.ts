// Veil — Ciphertext disguise layer (v3: invite/reply protocol with nonce + timestamp)
// Tags are reliable across all messengers and trivial to find in the DOM.

import type { HandshakePayload } from './types';

// Tag format: [VL:X]payload[/VL]
// I = invite (handshake initiation), R = reply (handshake response)
// E = encrypted message, V = verify fingerprint, X = end session
const TAG_I_OPEN = '[VL:I]';
const TAG_R_OPEN = '[VL:R]';
const TAG_E_OPEN = '[VL:E]';
const TAG_V_OPEN = '[VL:V]';
const TAG_X_OPEN = '[VL:X]';
const TAG_CLOSE  = '[/VL]';

// Detects any Veil message without knowing the type
function isAnyVeil(text: string): boolean {
  return text.includes('[VL:');
}

// --- Shared handshake payload parsing ---
// Payload format: pubkey.sig.nonce.timestamp (4 dot-separated fields)

function parseHandshakePayload(payload: string): HandshakePayload | null {
  const parts = payload.split('.');
  if (parts.length !== 4) return null;
  const timestamp = parseInt(parts[3], 10);
  if (isNaN(timestamp)) return null;
  return {
    publicKey: parts[0],
    signature: parts[1],
    nonce: parts[2],
    timestamp,
  };
}

function formatHandshakePayload(publicKey: string, signature: string, nonce: string, timestamp: number): string {
  return `${publicKey}.${signature}.${nonce}.${timestamp}`;
}

// --- Invite ---

function wrapInvite(publicKey: string, signature: string, nonce: string, timestamp: number): string {
  return `${TAG_I_OPEN}${formatHandshakePayload(publicKey, signature, nonce, timestamp)}${TAG_CLOSE}`;
}

function unwrapInvite(text: string): HandshakePayload | null {
  const start = text.indexOf(TAG_I_OPEN);
  if (start === -1) return null;
  const payloadStart = start + TAG_I_OPEN.length;
  const end = text.indexOf(TAG_CLOSE, payloadStart);
  if (end === -1) return null;
  return parseHandshakePayload(text.slice(payloadStart, end));
}

function isInvite(text: string): boolean {
  return text.includes(TAG_I_OPEN);
}

// --- Reply ---

function wrapReply(publicKey: string, signature: string, nonce: string, timestamp: number): string {
  return `${TAG_R_OPEN}${formatHandshakePayload(publicKey, signature, nonce, timestamp)}${TAG_CLOSE}`;
}

function unwrapReply(text: string): HandshakePayload | null {
  const start = text.indexOf(TAG_R_OPEN);
  if (start === -1) return null;
  const payloadStart = start + TAG_R_OPEN.length;
  const end = text.indexOf(TAG_CLOSE, payloadStart);
  if (end === -1) return null;
  return parseHandshakePayload(text.slice(payloadStart, end));
}

function isReply(text: string): boolean {
  return text.includes(TAG_R_OPEN);
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

// --- End session ---

function wrapEnd(encryptedTimestamp: string): string {
  return `${TAG_X_OPEN}${encryptedTimestamp}${TAG_CLOSE}`;
}

function unwrapEnd(text: string): string | null {
  const start = text.indexOf(TAG_X_OPEN);
  if (start === -1) return null;
  const payloadStart = start + TAG_X_OPEN.length;
  const end = text.indexOf(TAG_CLOSE, payloadStart);
  if (end === -1) return null;
  return text.slice(payloadStart, end);
}

function isEndMessage(text: string): boolean {
  return text.includes(TAG_X_OPEN);
}

export const VeilDisguise = {
  isAnyVeil,
  wrapInvite,
  unwrapInvite,
  isInvite,
  wrapReply,
  unwrapReply,
  isReply,
  wrapMessage,
  unwrapMessage,
  isVeilMessage,
  wrapVerify,
  unwrapVerify,
  isVerifyMessage,
  wrapEnd,
  unwrapEnd,
  isEndMessage,
  TAG_I_OPEN,
  TAG_R_OPEN,
  TAG_E_OPEN,
  TAG_V_OPEN,
  TAG_X_OPEN,
  TAG_CLOSE,
};
