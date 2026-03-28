// Veil — WebCrypto operations (ECDH P-256 + AES-256-GCM + HKDF)
// Zero dependencies — uses only window.crypto.subtle

const IV_LENGTH = 12; // 96-bit IV for AES-GCM
const TAG_LENGTH = 128; // 128-bit auth tag

// HMAC provenance key — used to tag handshake messages as genuine Veil messages
// This is a speed bump, not a secret (see spec: Layer 1 MITM protection)
const PROVENANCE_KEY_RAW = new Uint8Array([
  86, 69, 73, 76, 45, 80, 82, 79, 86, 69, 78, 65, 78, 67, 69, 45,
  75, 69, 89, 45, 50, 48, 50, 54, 45, 86, 49, 45, 83, 69, 67, 82,
]);

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits'],
  )) as CryptoKeyPair;
}

async function exportPublicKey(keyPair: CryptoKeyPair): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  return arrayBufferToBase64(raw);
}

async function importPublicKey(base64: string): Promise<CryptoKey> {
  const raw = base64ToArrayBuffer(base64);
  return await crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}

async function exportPrivateKey(keyPair: CryptoKeyPair): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  return JSON.stringify(jwk);
}

async function importPrivateKey(jwkString: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkString) as JsonWebKey;
  return await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits'],
  );
}

async function deriveSharedKey(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('veil-v1-salt'),
      info: new TextEncoder().encode('veil-v1-aes-key'),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encrypt(aesKey: CryptoKey, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: TAG_LENGTH },
    aesKey,
    encoded,
  );
  const result = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), IV_LENGTH);
  return arrayBufferToBase64(result.buffer);
}

async function decrypt(aesKey: CryptoKey, base64Payload: string): Promise<string> {
  const data = new Uint8Array(base64ToArrayBuffer(base64Payload));
  const iv = data.slice(0, IV_LENGTH);
  const ciphertext = data.slice(IV_LENGTH);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: TAG_LENGTH },
    aesKey,
    ciphertext,
  );
  return new TextDecoder().decode(decrypted);
}

async function computeFingerprint(
  publicKeyA: string,
  publicKeyB: string,
): Promise<string> {
  // Sort lexicographically so both sides compute the same fingerprint
  const [first, second] = [publicKeyA, publicKeyB].sort();
  const combined = first + ':' + second;
  const encoded = new TextEncoder().encode(combined);
  const hash = await crypto.subtle.digest('SHA-256', encoded);
  const bytes = new Uint8Array(hash);
  return Array.from(bytes.slice(0, 4))
    .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
    .join('-');
}

async function getProvenanceKey(): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    'raw',
    PROVENANCE_KEY_RAW,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

async function signProvenance(publicKeyBase64: string): Promise<string> {
  const key = await getProvenanceKey();
  const data = new TextEncoder().encode(publicKeyBase64);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return arrayBufferToBase64(sig);
}

async function verifyProvenance(publicKeyBase64: string, signatureBase64: string): Promise<boolean> {
  const key = await getProvenanceKey();
  const data = new TextEncoder().encode(publicKeyBase64);
  const sig = base64ToArrayBuffer(signatureBase64);
  return await crypto.subtle.verify('HMAC', key, sig, data);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export const VeilCrypto = {
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
  base64ToArrayBuffer,
};
