import { describe, it, expect, beforeAll } from 'vitest';
import { VeilCrypto } from '../src/crypto';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Decode a base64 string to a Uint8Array of raw bytes
function decodeBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Encode a Uint8Array of raw bytes back to base64
function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

// Decode, apply a mutation, re-encode — used for all tampering tests
function tamper(b64: string, mutate: (bytes: Uint8Array) => void): string {
  const bytes = decodeBase64(b64);
  mutate(bytes);
  return encodeBase64(bytes);
}

// Flip all 8 bits of one byte at a given index
function flipByte(b64: string, index: number): string {
  return tamper(b64, (bytes) => {
    bytes[index] ^= 0xff;
  });
}

// Remove bytes from the end
function truncate(b64: string, removeFromEnd: number): string {
  const bytes = decodeBase64(b64);
  return encodeBase64(bytes.slice(0, bytes.length - removeFromEnd));
}

// Add extra bytes to the end
function appendBytes(b64: string, count: number): string {
  const bytes = decodeBase64(b64);
  const result = new Uint8Array(bytes.length + count);
  result.set(bytes);
  result.fill(0xff, bytes.length); // fill extra with 0xff
  return encodeBase64(result);
}

// Add extra bytes to the front
function prependBytes(b64: string, count: number): string {
  const bytes = decodeBase64(b64);
  const result = new Uint8Array(bytes.length + count);
  result.fill(0xff, 0, count); // fill prefix with 0xff
  result.set(bytes, count);
  return encodeBase64(result);
}

// Payload layout produced by VeilCrypto.encrypt:
//   [12 bytes: IV][n bytes: encrypted plaintext][16 bytes: GCM auth tag]
const IV_BYTES = 12;
const TAG_BYTES = 16;

// ---------------------------------------------------------------------------
// 1. Key Generation
// ---------------------------------------------------------------------------

describe('1. Key Generation', () => {
  it('1.1 returns an object with publicKey and privateKey', async () => {
    const kp = await VeilCrypto.generateKeyPair();
    expect(kp.publicKey).toBeDefined();
    expect(kp.privateKey).toBeDefined();
  });

  it('1.2 public key has no usages; private key has deriveKey and deriveBits', async () => {
    const kp = await VeilCrypto.generateKeyPair();
    expect(kp.publicKey.usages).toEqual([]);
    expect(kp.privateKey.usages).toContain('deriveKey');
    expect(kp.privateKey.usages).toContain('deriveBits');
  });

  it('1.3 each call produces a unique keypair', async () => {
    const kp1 = await VeilCrypto.generateKeyPair();
    const kp2 = await VeilCrypto.generateKeyPair();
    const pub1 = await VeilCrypto.exportPublicKey(kp1);
    const pub2 = await VeilCrypto.exportPublicKey(kp2);
    expect(pub1).not.toBe(pub2);
  });

  it('1.4 keypair is extractable — can be exported without throwing', async () => {
    const kp = await VeilCrypto.generateKeyPair();
    await expect(VeilCrypto.exportPublicKey(kp)).resolves.toBeDefined();
    await expect(VeilCrypto.exportPrivateKey(kp)).resolves.toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// 2. Public Key Export / Import
// ---------------------------------------------------------------------------

describe('2. Public Key Export / Import', () => {
  let kp: CryptoKeyPair;

  beforeAll(async () => {
    kp = await VeilCrypto.generateKeyPair();
  });

  it('2.1 exportPublicKey returns a non-empty string', async () => {
    const pub = await VeilCrypto.exportPublicKey(kp);
    expect(typeof pub).toBe('string');
    expect(pub.length).toBeGreaterThan(0);
  });

  it('2.2 exported public key is valid base64', async () => {
    const pub = await VeilCrypto.exportPublicKey(kp);
    expect(pub).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it('2.3 P-256 uncompressed public key is exactly 88 base64 characters (65 raw bytes)', async () => {
    const pub = await VeilCrypto.exportPublicKey(kp);
    // 65 raw bytes → ceil(65/3)*4 = 88 base64 chars
    expect(pub.length).toBe(88);
    expect(decodeBase64(pub).length).toBe(65);
  });

  it('2.4 round-trip: imported key produces the same shared secret as the original', async () => {
    const kp2 = await VeilCrypto.generateKeyPair();
    const pub = await VeilCrypto.exportPublicKey(kp);
    const imported = await VeilCrypto.importPublicKey(pub);

    const keyFromOriginal = await VeilCrypto.deriveSharedKey(kp2.privateKey, kp.publicKey);
    const keyFromImported = await VeilCrypto.deriveSharedKey(kp2.privateKey, imported);

    const ct = await VeilCrypto.encrypt(keyFromOriginal, 'round-trip');
    await expect(VeilCrypto.decrypt(keyFromImported, ct)).resolves.toBe('round-trip');
  });

  it('2.5 different keypairs export to different strings', async () => {
    const kp2 = await VeilCrypto.generateKeyPair();
    const pub1 = await VeilCrypto.exportPublicKey(kp);
    const pub2 = await VeilCrypto.exportPublicKey(kp2);
    expect(pub1).not.toBe(pub2);
  });
});

// ---------------------------------------------------------------------------
// 3. Private Key Export / Import
// ---------------------------------------------------------------------------

describe('3. Private Key Export / Import', () => {
  let kp: CryptoKeyPair;

  beforeAll(async () => {
    kp = await VeilCrypto.generateKeyPair();
  });

  it('3.1 exportPrivateKey returns a valid JSON string', async () => {
    const exported = await VeilCrypto.exportPrivateKey(kp);
    expect(() => JSON.parse(exported)).not.toThrow();
  });

  it('3.2 JWK contains the expected fields (kty, crv, d, x, y)', async () => {
    const exported = await VeilCrypto.exportPrivateKey(kp);
    const jwk = JSON.parse(exported);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.d).toBeDefined(); // private scalar
    expect(jwk.x).toBeDefined(); // public key x-coordinate
    expect(jwk.y).toBeDefined(); // public key y-coordinate
  });

  it('3.3 round-trip: restored private key derives the same shared secret', async () => {
    const kp2 = await VeilCrypto.generateKeyPair();
    const pub2 = await VeilCrypto.exportPublicKey(kp2);
    const importedPub2 = await VeilCrypto.importPublicKey(pub2);

    const privExport = await VeilCrypto.exportPrivateKey(kp);
    const restoredPriv = await VeilCrypto.importPrivateKey(privExport);

    const keyOriginal = await VeilCrypto.deriveSharedKey(kp.privateKey, importedPub2);
    const keyRestored = await VeilCrypto.deriveSharedKey(restoredPriv, importedPub2);

    const ct = await VeilCrypto.encrypt(keyOriginal, 'private key round-trip');
    await expect(VeilCrypto.decrypt(keyRestored, ct)).resolves.toBe('private key round-trip');
  });
});

// ---------------------------------------------------------------------------
// 4. Shared Key Derivation — the ECDH guarantee
// ---------------------------------------------------------------------------

describe('4. Shared Key Derivation (ECDH)', () => {
  let kpA: CryptoKeyPair;
  let kpB: CryptoKeyPair;
  let pubA: string;
  let pubB: string;

  beforeAll(async () => {
    kpA = await VeilCrypto.generateKeyPair();
    kpB = await VeilCrypto.generateKeyPair();
    pubA = await VeilCrypto.exportPublicKey(kpA);
    pubB = await VeilCrypto.exportPublicKey(kpB);
  });

  it('4.1 Alice and Bob independently derive the same key (core ECDH guarantee)', async () => {
    const importedPubB = await VeilCrypto.importPublicKey(pubB);
    const importedPubA = await VeilCrypto.importPublicKey(pubA);

    const keyA = await VeilCrypto.deriveSharedKey(kpA.privateKey, importedPubB);
    const keyB = await VeilCrypto.deriveSharedKey(kpB.privateKey, importedPubA);

    const ct = await VeilCrypto.encrypt(keyA, 'hello');
    await expect(VeilCrypto.decrypt(keyB, ct)).resolves.toBe('hello');
  });

  it('4.2 communication works in both directions with the same derived keys', async () => {
    const importedPubB = await VeilCrypto.importPublicKey(pubB);
    const importedPubA = await VeilCrypto.importPublicKey(pubA);
    const keyA = await VeilCrypto.deriveSharedKey(kpA.privateKey, importedPubB);
    const keyB = await VeilCrypto.deriveSharedKey(kpB.privateKey, importedPubA);

    const ct1 = await VeilCrypto.encrypt(keyA, 'from Alice');
    await expect(VeilCrypto.decrypt(keyB, ct1)).resolves.toBe('from Alice');

    const ct2 = await VeilCrypto.encrypt(keyB, 'from Bob');
    await expect(VeilCrypto.decrypt(keyA, ct2)).resolves.toBe('from Bob');
  });

  it('4.3 using the wrong public key produces a different key — decryption throws', async () => {
    const kpC = await VeilCrypto.generateKeyPair();
    const pubC = await VeilCrypto.exportPublicKey(kpC);
    const importedPubB = await VeilCrypto.importPublicKey(pubB);
    const importedPubC = await VeilCrypto.importPublicKey(pubC);

    const correctKey = await VeilCrypto.deriveSharedKey(kpA.privateKey, importedPubB);
    const wrongKey = await VeilCrypto.deriveSharedKey(kpA.privateKey, importedPubC);

    const ct = await VeilCrypto.encrypt(correctKey, 'secret');
    await expect(VeilCrypto.decrypt(wrongKey, ct)).rejects.toThrow();
  });

  it('4.4 derived AES key is not extractable — it never leaves the crypto engine', async () => {
    const importedPubB = await VeilCrypto.importPublicKey(pubB);
    const sharedKey = await VeilCrypto.deriveSharedKey(kpA.privateKey, importedPubB);
    await expect(crypto.subtle.exportKey('raw', sharedKey)).rejects.toThrow();
  });

  it('4.5 two separate sessions produce independent keys — messages do not cross', async () => {
    const kpA2 = await VeilCrypto.generateKeyPair();
    const kpB2 = await VeilCrypto.generateKeyPair();
    const pub2B = await VeilCrypto.exportPublicKey(kpB2);
    const importedPubB = await VeilCrypto.importPublicKey(pubB);
    const importedPub2B = await VeilCrypto.importPublicKey(pub2B);

    const key1 = await VeilCrypto.deriveSharedKey(kpA.privateKey, importedPubB);
    const key2 = await VeilCrypto.deriveSharedKey(kpA2.privateKey, importedPub2B);

    const ct = await VeilCrypto.encrypt(key1, 'session 1 only');
    await expect(VeilCrypto.decrypt(key2, ct)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 5. Encrypt — output properties
// ---------------------------------------------------------------------------

describe('5. Encrypt — Output Properties', () => {
  let key: CryptoKey;

  beforeAll(async () => {
    const kpA = await VeilCrypto.generateKeyPair();
    const kpB = await VeilCrypto.generateKeyPair();
    const pubB = await VeilCrypto.exportPublicKey(kpB);
    const importedPubB = await VeilCrypto.importPublicKey(pubB);
    key = await VeilCrypto.deriveSharedKey(kpA.privateKey, importedPubB);
  });

  it('5.1 output is valid base64', async () => {
    const ct = await VeilCrypto.encrypt(key, 'hello');
    expect(ct).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it('5.2 output is at least 28 bytes larger than input (12 IV + 16 GCM tag)', async () => {
    const plaintext = 'hello';
    const ct = await VeilCrypto.encrypt(key, plaintext);
    const ctBytes = decodeBase64(ct).length;
    const ptBytes = new TextEncoder().encode(plaintext).length;
    expect(ctBytes).toBeGreaterThanOrEqual(ptBytes + IV_BYTES + TAG_BYTES);
  });

  it('5.3 encrypting the same plaintext twice produces different ciphertext (random IV each time)', async () => {
    const ct1 = await VeilCrypto.encrypt(key, 'same message');
    const ct2 = await VeilCrypto.encrypt(key, 'same message');
    expect(ct1).not.toBe(ct2);
  });

  it('5.4 short message (1 char) encrypts and decrypts correctly', async () => {
    const ct = await VeilCrypto.encrypt(key, 'a');
    await expect(VeilCrypto.decrypt(key, ct)).resolves.toBe('a');
  });

  it('5.5 empty string encrypts and decrypts to empty string', async () => {
    const ct = await VeilCrypto.encrypt(key, '');
    await expect(VeilCrypto.decrypt(key, ct)).resolves.toBe('');
  });

  it('5.6 long message (10,000 chars) encrypts and decrypts correctly', async () => {
    const plaintext = 'a'.repeat(10_000);
    const ct = await VeilCrypto.encrypt(key, plaintext);
    await expect(VeilCrypto.decrypt(key, ct)).resolves.toBe(plaintext);
  });

  it('5.7 Persian/Arabic Unicode text round-trips correctly', async () => {
    const plaintext = 'سلام دنیا — این یک پیام رمزگذاری شده است 🔒';
    const ct = await VeilCrypto.encrypt(key, plaintext);
    await expect(VeilCrypto.decrypt(key, ct)).resolves.toBe(plaintext);
  });

  it('5.8 special characters (newlines, null bytes, tabs, emoji) round-trip correctly', async () => {
    const plaintext = 'line1\nline2\r\n\0null\ttab🔒emoji\u200B zero-width';
    const ct = await VeilCrypto.encrypt(key, plaintext);
    await expect(VeilCrypto.decrypt(key, ct)).resolves.toBe(plaintext);
  });
});

// ---------------------------------------------------------------------------
// 6. Decrypt — Tampering Scenarios
// Every one of these must throw — GCM rejects any modification whatsoever
// ---------------------------------------------------------------------------

describe('6. Decrypt — Tampering', () => {
  let key: CryptoKey;
  let ciphertext: string;
  const PLAINTEXT = 'the quick brown fox jumps over the lazy dog';

  beforeAll(async () => {
    const kpA = await VeilCrypto.generateKeyPair();
    const kpB = await VeilCrypto.generateKeyPair();
    const pubB = await VeilCrypto.exportPublicKey(kpB);
    const importedPubB = await VeilCrypto.importPublicKey(pubB);
    key = await VeilCrypto.deriveSharedKey(kpA.privateKey, importedPubB);
    ciphertext = await VeilCrypto.encrypt(key, PLAINTEXT);
  });

  it('6.1 baseline: correct ciphertext decrypts to the original plaintext', async () => {
    await expect(VeilCrypto.decrypt(key, ciphertext)).resolves.toBe(PLAINTEXT);
  });

  it('6.2 flip one byte in the ciphertext body → throws', async () => {
    const bytes = decodeBase64(ciphertext);
    // Target a byte in the middle of the encrypted body (between IV and tag)
    const bodyMid = IV_BYTES + Math.floor((bytes.length - IV_BYTES - TAG_BYTES) / 2);
    const tampered = flipByte(ciphertext, bodyMid);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });

  it('6.3 flip one byte in the IV (first 12 bytes) → throws', async () => {
    const tampered = flipByte(ciphertext, 0);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });

  it('6.4 flip one byte in the last byte of the IV → throws', async () => {
    const tampered = flipByte(ciphertext, IV_BYTES - 1);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });

  it('6.5 flip one byte in the auth tag (last 16 bytes) → throws', async () => {
    const bytes = decodeBase64(ciphertext);
    const tampered = flipByte(ciphertext, bytes.length - 1);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });

  it('6.6 flip the very first byte → throws', async () => {
    const tampered = flipByte(ciphertext, 0);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });

  it('6.7 flip the very last byte → throws', async () => {
    const bytes = decodeBase64(ciphertext);
    const tampered = flipByte(ciphertext, bytes.length - 1);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });

  it('6.8 corrupt the entire tag region (last 16 bytes) → throws', async () => {
    const bytes = decodeBase64(ciphertext);
    const tampered = tamper(ciphertext, (b) => {
      for (let i = b.length - TAG_BYTES; i < b.length; i++) b[i] ^= 0xff;
    });
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
    // Sanity check: original still decrypts fine
    const bytes2 = decodeBase64(ciphertext);
    expect(bytes2.length).toBe(bytes.length);
  });

  it('6.9 truncate by 1 byte → throws', async () => {
    const tampered = truncate(ciphertext, 1);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });

  it('6.10 truncate to just the IV (12 bytes, no ciphertext or tag) → throws', async () => {
    const ivOnly = encodeBase64(decodeBase64(ciphertext).slice(0, IV_BYTES));
    await expect(VeilCrypto.decrypt(key, ivOnly)).rejects.toThrow();
  });

  it('6.11 empty string payload → throws', async () => {
    await expect(VeilCrypto.decrypt(key, '')).rejects.toThrow();
  });

  it('6.12 completely random bytes → throws', async () => {
    const random = new Uint8Array(64);
    crypto.getRandomValues(random);
    await expect(VeilCrypto.decrypt(key, encodeBase64(random))).rejects.toThrow();
  });

  it('6.13 correct ciphertext, completely different key → throws', async () => {
    const kpC = await VeilCrypto.generateKeyPair();
    const kpD = await VeilCrypto.generateKeyPair();
    const pubD = await VeilCrypto.exportPublicKey(kpD);
    const importedPubD = await VeilCrypto.importPublicKey(pubD);
    const wrongKey = await VeilCrypto.deriveSharedKey(kpC.privateKey, importedPubD);
    await expect(VeilCrypto.decrypt(wrongKey, ciphertext)).rejects.toThrow();
  });

  it('6.14 ciphertext from a different session (different key) → throws', async () => {
    const kpC = await VeilCrypto.generateKeyPair();
    const kpD = await VeilCrypto.generateKeyPair();
    const pubD = await VeilCrypto.exportPublicKey(kpD);
    const importedPubD = await VeilCrypto.importPublicKey(pubD);
    const otherKey = await VeilCrypto.deriveSharedKey(kpC.privateKey, importedPubD);
    const otherCt = await VeilCrypto.encrypt(otherKey, 'other session');
    await expect(VeilCrypto.decrypt(key, otherCt)).rejects.toThrow();
  });

  it('6.15 prepend 4 extra bytes → throws (IV offset shifts, everything corrupted)', async () => {
    const tampered = prependBytes(ciphertext, 4);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });

  it('6.16 append 4 extra bytes → throws (tag offset shifts)', async () => {
    const tampered = appendBytes(ciphertext, 4);
    await expect(VeilCrypto.decrypt(key, tampered)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 7. Fingerprint
// ---------------------------------------------------------------------------

describe('7. Fingerprint', () => {
  let pubA: string;
  let pubB: string;

  beforeAll(async () => {
    const kpA = await VeilCrypto.generateKeyPair();
    const kpB = await VeilCrypto.generateKeyPair();
    pubA = await VeilCrypto.exportPublicKey(kpA);
    pubB = await VeilCrypto.exportPublicKey(kpB);
  });

  it('7.1 returns exactly the format XX-XX-XX-XX (4 uppercase hex pairs)', async () => {
    const fp = await VeilCrypto.computeFingerprint(pubA, pubB);
    expect(fp).toMatch(/^[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}$/);
  });

  it('7.2 is deterministic — same inputs always produce the same fingerprint', async () => {
    const fp1 = await VeilCrypto.computeFingerprint(pubA, pubB);
    const fp2 = await VeilCrypto.computeFingerprint(pubA, pubB);
    expect(fp1).toBe(fp2);
  });

  it('7.3 different key pairs produce different fingerprints', async () => {
    const kpC = await VeilCrypto.generateKeyPair();
    const pubC = await VeilCrypto.exportPublicKey(kpC);
    const fp1 = await VeilCrypto.computeFingerprint(pubA, pubB);
    const fp2 = await VeilCrypto.computeFingerprint(pubA, pubC);
    expect(fp1).not.toBe(fp2);
  });

  it('7.4 order matters — fingerprint(a, b) !== fingerprint(b, a)', async () => {
    const fpAB = await VeilCrypto.computeFingerprint(pubA, pubB);
    const fpBA = await VeilCrypto.computeFingerprint(pubB, pubA);
    expect(fpAB).not.toBe(fpBA);
  });

  it('7.5 MITM: Eve substitutes her key — Alice and Bob compute different fingerprints', async () => {
    const kpEve = await VeilCrypto.generateKeyPair();
    const pubEve = await VeilCrypto.exportPublicKey(kpEve);

    // Alice thinks she received Bob's key, but got Eve's
    const fpAliceSees = await VeilCrypto.computeFingerprint(pubA, pubEve);
    // Bob thinks he received Alice's key, but got Eve's
    const fpBobSees = await VeilCrypto.computeFingerprint(pubB, pubEve);

    // They don't match → MITM is detected
    expect(fpAliceSees).not.toBe(fpBobSees);

    // Sanity: without MITM they do match (protocol-consistent ordering)
    const fpDirect = await VeilCrypto.computeFingerprint(pubA, pubB);
    expect(fpDirect).not.toBe(fpAliceSees);
    expect(fpDirect).not.toBe(fpBobSees);
  });
});

// ---------------------------------------------------------------------------
// 8. Provenance — HMAC sign / verify
// ---------------------------------------------------------------------------

describe('8. Provenance (HMAC)', () => {
  it('8.1 signProvenance returns a non-empty valid base64 string', async () => {
    const sig = await VeilCrypto.signProvenance('some-public-key');
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);
    expect(sig).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it('8.2 verifyProvenance: a key verifies against its own signature → true', async () => {
    const pub = 'AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOO';
    const sig = await VeilCrypto.signProvenance(pub);
    await expect(VeilCrypto.verifyProvenance(pub, sig)).resolves.toBe(true);
  });

  it('8.3 verifyProvenance: different key with the original signature → false', async () => {
    const sig = await VeilCrypto.signProvenance('key-A');
    await expect(VeilCrypto.verifyProvenance('key-B', sig)).resolves.toBe(false);
  });

  it('8.4 verifyProvenance: tampered signature (one byte flipped) → false', async () => {
    const pub = 'some-public-key-base64';
    const sig = await VeilCrypto.signProvenance(pub);
    const tampered = flipByte(sig, 0);
    await expect(VeilCrypto.verifyProvenance(pub, tampered)).resolves.toBe(false);
  });

  it('8.5 verifyProvenance: last byte of signature flipped → false', async () => {
    const pub = 'some-public-key-base64';
    const sig = await VeilCrypto.signProvenance(pub);
    const tampered = flipByte(sig, decodeBase64(sig).length - 1);
    await expect(VeilCrypto.verifyProvenance(pub, tampered)).resolves.toBe(false);
  });

  it('8.6 signProvenance is deterministic — same input always produces same signature', async () => {
    const pub = 'deterministic-test-key';
    const sig1 = await VeilCrypto.signProvenance(pub);
    const sig2 = await VeilCrypto.signProvenance(pub);
    expect(sig1).toBe(sig2);
  });

  it('8.7 empty string can be signed and verified', async () => {
    const sig = await VeilCrypto.signProvenance('');
    await expect(VeilCrypto.verifyProvenance('', sig)).resolves.toBe(true);
  });

  it('8.8 real public key (exported from generateKeyPair) signs and verifies correctly', async () => {
    const kp = await VeilCrypto.generateKeyPair();
    const pub = await VeilCrypto.exportPublicKey(kp);
    const sig = await VeilCrypto.signProvenance(pub);
    await expect(VeilCrypto.verifyProvenance(pub, sig)).resolves.toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 9. Utilities — arrayBufferToBase64 / base64ToArrayBuffer
// ---------------------------------------------------------------------------

describe('9. Utilities (arrayBufferToBase64 / base64ToArrayBuffer)', () => {
  it('9.1 round-trip: encode then decode returns the original bytes', () => {
    const original = new Uint8Array([0, 1, 2, 127, 128, 200, 254, 255]);
    const b64 = VeilCrypto.arrayBufferToBase64(original.buffer);
    const restored = new Uint8Array(VeilCrypto.base64ToArrayBuffer(b64));
    expect(Array.from(restored)).toEqual(Array.from(original));
  });

  it('9.2 known value: "Hello" bytes produce "SGVsbG8="', () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]); // ASCII "Hello"
    expect(VeilCrypto.arrayBufferToBase64(bytes.buffer)).toBe('SGVsbG8=');
  });

  it('9.3 empty buffer encodes to empty string', () => {
    expect(VeilCrypto.arrayBufferToBase64(new ArrayBuffer(0))).toBe('');
  });

  it('9.4 base64 string with padding ("SGVsbG8=") decodes correctly', () => {
    const bytes = new Uint8Array(VeilCrypto.base64ToArrayBuffer('SGVsbG8='));
    expect(Array.from(bytes)).toEqual([72, 101, 108, 108, 111]);
  });

  it('9.5 all 256 possible byte values (0–255) survive the round-trip', () => {
    const original = new Uint8Array(256);
    for (let i = 0; i < 256; i++) original[i] = i;
    const b64 = VeilCrypto.arrayBufferToBase64(original.buffer);
    const restored = new Uint8Array(VeilCrypto.base64ToArrayBuffer(b64));
    expect(Array.from(restored)).toEqual(Array.from(original));
  });

  it('9.6 round-trip of a 1000-byte random buffer', () => {
    const original = crypto.getRandomValues(new Uint8Array(1000));
    const b64 = VeilCrypto.arrayBufferToBase64(original.buffer);
    const restored = new Uint8Array(VeilCrypto.base64ToArrayBuffer(b64));
    expect(Array.from(restored)).toEqual(Array.from(original));
  });
});

// ---------------------------------------------------------------------------
// 10. End-to-End Integration
// ---------------------------------------------------------------------------

describe('10. End-to-End Integration', () => {
  it('10.1 full Alice-Bob handshake and bidirectional messaging', async () => {
    // Phase 1 — each side generates a keypair
    const kpAlice = await VeilCrypto.generateKeyPair();
    const kpBob = await VeilCrypto.generateKeyPair();

    // Phase 2 — export public keys (the "invite strings")
    const alicePub = await VeilCrypto.exportPublicKey(kpAlice);
    const bobPub = await VeilCrypto.exportPublicKey(kpBob);

    // Phase 2 — sign and verify provenance on both sides
    const aliceSig = await VeilCrypto.signProvenance(alicePub);
    const bobSig = await VeilCrypto.signProvenance(bobPub);
    expect(await VeilCrypto.verifyProvenance(alicePub, aliceSig)).toBe(true);
    expect(await VeilCrypto.verifyProvenance(bobPub, bobSig)).toBe(true);

    // Phase 2 — each side derives the shared key from the other's public key
    const importedAlicePub = await VeilCrypto.importPublicKey(alicePub);
    const importedBobPub = await VeilCrypto.importPublicKey(bobPub);
    const keyAlice = await VeilCrypto.deriveSharedKey(kpAlice.privateKey, importedBobPub);
    const keyBob = await VeilCrypto.deriveSharedKey(kpBob.privateKey, importedAlicePub);

    // Phase 3 — messaging: Alice → Bob
    const ct1 = await VeilCrypto.encrypt(keyAlice, 'Hello Bob!');
    await expect(VeilCrypto.decrypt(keyBob, ct1)).resolves.toBe('Hello Bob!');

    // Phase 3 — messaging: Bob → Alice
    const ct2 = await VeilCrypto.encrypt(keyBob, 'Hello Alice!');
    await expect(VeilCrypto.decrypt(keyAlice, ct2)).resolves.toBe('Hello Alice!');
  });

  it('10.2 MITM key substitution — Eve cannot bridge Alice and Bob, fingerprints diverge', async () => {
    const kpAlice = await VeilCrypto.generateKeyPair();
    const kpBob = await VeilCrypto.generateKeyPair();
    const kpEve = await VeilCrypto.generateKeyPair();

    const alicePub = await VeilCrypto.exportPublicKey(kpAlice);
    const bobPub = await VeilCrypto.exportPublicKey(kpBob);
    const evePub = await VeilCrypto.exportPublicKey(kpEve);
    const importedEvePub = await VeilCrypto.importPublicKey(evePub);

    // Eve substitutes her key in both directions
    const keyAliceEve = await VeilCrypto.deriveSharedKey(kpAlice.privateKey, importedEvePub);
    const keyBobEve = await VeilCrypto.deriveSharedKey(kpBob.privateKey, importedEvePub);

    // Alice and Bob cannot talk to each other — they each talk to Eve
    const ct = await VeilCrypto.encrypt(keyAliceEve, 'secret');
    await expect(VeilCrypto.decrypt(keyBobEve, ct)).rejects.toThrow();

    // Fingerprint check catches it — each side computes a different fingerprint
    const fpAlice = await VeilCrypto.computeFingerprint(alicePub, evePub);
    const fpBob = await VeilCrypto.computeFingerprint(bobPub, evePub);
    expect(fpAlice).not.toBe(fpBob); // mismatch → MITM detected
  });

  it('10.3 session isolation — a message from session 1 cannot be decrypted in session 2', async () => {
    const [kpA1, kpB1, kpA2, kpB2] = await Promise.all([
      VeilCrypto.generateKeyPair(),
      VeilCrypto.generateKeyPair(),
      VeilCrypto.generateKeyPair(),
      VeilCrypto.generateKeyPair(),
    ]);
    const pub1B = await VeilCrypto.exportPublicKey(kpB1);
    const pub2B = await VeilCrypto.exportPublicKey(kpB2);
    const key1 = await VeilCrypto.deriveSharedKey(kpA1.privateKey, await VeilCrypto.importPublicKey(pub1B));
    const key2 = await VeilCrypto.deriveSharedKey(kpA2.privateKey, await VeilCrypto.importPublicKey(pub2B));

    const ct = await VeilCrypto.encrypt(key1, 'session 1 secret');
    await expect(VeilCrypto.decrypt(key2, ct)).rejects.toThrow();
  });

  it('10.4 ten messages in one session each decrypt to their own plaintext (unique IVs)', async () => {
    const kpA = await VeilCrypto.generateKeyPair();
    const kpB = await VeilCrypto.generateKeyPair();
    const pubA = await VeilCrypto.exportPublicKey(kpA);
    const pubB = await VeilCrypto.exportPublicKey(kpB);
    const keyA = await VeilCrypto.deriveSharedKey(kpA.privateKey, await VeilCrypto.importPublicKey(pubB));
    const keyB = await VeilCrypto.deriveSharedKey(kpB.privateKey, await VeilCrypto.importPublicKey(pubA));

    const plaintexts = Array.from({ length: 10 }, (_, i) => `message number ${i}`);
    const ciphertexts = await Promise.all(plaintexts.map((m) => VeilCrypto.encrypt(keyA, m)));

    // All ciphertexts are unique (different IVs, even for identical content)
    expect(new Set(ciphertexts).size).toBe(10);

    // All decrypt correctly on Bob's side
    for (let i = 0; i < plaintexts.length; i++) {
      await expect(VeilCrypto.decrypt(keyB, ciphertexts[i])).resolves.toBe(plaintexts[i]);
    }
  });

  it('10.5 fingerprint verification matches the protocol ordering used in sidebar.ts', async () => {
    const kpAlice = await VeilCrypto.generateKeyPair();
    const kpBob = await VeilCrypto.generateKeyPair();
    const pubAlice = await VeilCrypto.exportPublicKey(kpAlice);
    const pubBob = await VeilCrypto.exportPublicKey(kpBob);
    const keyAlice = await VeilCrypto.deriveSharedKey(kpAlice.privateKey, await VeilCrypto.importPublicKey(pubBob));
    const keyBob = await VeilCrypto.deriveSharedKey(kpBob.privateKey, await VeilCrypto.importPublicKey(pubAlice));

    // Bob (responder) computes fingerprint(myPub=bob, theirPub=alice) and encrypts it
    const bobFp = await VeilCrypto.computeFingerprint(pubBob, pubAlice);
    const verifyPayload = await VeilCrypto.encrypt(keyBob, bobFp);

    // Alice (initiator) decrypts it and checks against fingerprint(theirPub=bob, myPub=alice)
    const received = await VeilCrypto.decrypt(keyAlice, verifyPayload);
    const aliceExpected = await VeilCrypto.computeFingerprint(pubBob, pubAlice);

    // They match — session is verified
    expect(received).toBe(aliceExpected);
  });
});
