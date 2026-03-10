import { describe, it, expect, beforeAll } from 'vitest';
import { VeilDisguise } from '../src/disguise';
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

// Flip one bit in a base64 payload — used to simulate tampering for crypto tests
function flipByte(b64: string, index: number): string {
  const bytes = decodeBase64(b64);
  bytes[index] ^= 0xff;
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

// A realistic base64 payload to use as a stand-in for real ciphertext
const FAKE_B64 = btoa('this is a fake ciphertext payload for testing');

// Full base64 alphabet — used to verify no false collision with [/VL]
const FULL_B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

// ---------------------------------------------------------------------------

describe('1. Constants', () => {
  it('all four tag constants are non-empty strings', () => {
    expect(typeof VeilDisguise.TAG_E_OPEN).toBe('string');
    expect(typeof VeilDisguise.TAG_H_OPEN).toBe('string');
    expect(typeof VeilDisguise.TAG_V_OPEN).toBe('string');
    expect(typeof VeilDisguise.TAG_CLOSE).toBe('string');
    expect(VeilDisguise.TAG_E_OPEN.length).toBeGreaterThan(0);
    expect(VeilDisguise.TAG_H_OPEN.length).toBeGreaterThan(0);
    expect(VeilDisguise.TAG_V_OPEN.length).toBeGreaterThan(0);
    expect(VeilDisguise.TAG_CLOSE.length).toBeGreaterThan(0);
  });

  it('all three open tags are distinct', () => {
    const tags = [VeilDisguise.TAG_E_OPEN, VeilDisguise.TAG_H_OPEN, VeilDisguise.TAG_V_OPEN];
    const unique = new Set(tags);
    expect(unique.size).toBe(3);
  });

  it('all open tags contain [VL: and close tag is [/VL]', () => {
    expect(VeilDisguise.TAG_E_OPEN).toContain('[VL:');
    expect(VeilDisguise.TAG_H_OPEN).toContain('[VL:');
    expect(VeilDisguise.TAG_V_OPEN).toContain('[VL:');
    expect(VeilDisguise.TAG_CLOSE).toBe('[/VL]');
  });
});

// ---------------------------------------------------------------------------

describe('2. isAnyVeil', () => {
  it('returns true for an E-tagged message', () => {
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapMessage(FAKE_B64))).toBe(true);
  });

  it('returns true for an H-tagged message', () => {
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64))).toBe(true);
  });

  it('returns true for a V-tagged message', () => {
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapVerify(FAKE_B64))).toBe(true);
  });

  it('returns false for plain text', () => {
    expect(VeilDisguise.isAnyVeil('hello, how are you?')).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(VeilDisguise.isAnyVeil('')).toBe(false);
  });

  it('is case-sensitive — lowercase tags are not detected', () => {
    expect(VeilDisguise.isAnyVeil('[vl:e]payload[/vl]')).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('3. Encrypted message — wrap / unwrap / is', () => {
  it('wrapMessage starts with TAG_E_OPEN and ends with TAG_CLOSE', () => {
    const wrapped = VeilDisguise.wrapMessage(FAKE_B64);
    expect(wrapped.startsWith(VeilDisguise.TAG_E_OPEN)).toBe(true);
    expect(wrapped.endsWith(VeilDisguise.TAG_CLOSE)).toBe(true);
  });

  it('wrapMessage places the payload exactly between the tags', () => {
    const wrapped = VeilDisguise.wrapMessage(FAKE_B64);
    const inner = wrapped.slice(VeilDisguise.TAG_E_OPEN.length, wrapped.length - VeilDisguise.TAG_CLOSE.length);
    expect(inner).toBe(FAKE_B64);
  });

  it('round-trip: unwrapMessage(wrapMessage(x)) === x', () => {
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapMessage(FAKE_B64))).toBe(FAKE_B64);
  });

  it('unwrapMessage works when the tag appears mid-string (sender name before it)', () => {
    const wrapped = `Alice: ${VeilDisguise.wrapMessage(FAKE_B64)}`;
    expect(VeilDisguise.unwrapMessage(wrapped)).toBe(FAKE_B64);
  });

  it('unwrapMessage works when surrounded by whitespace and newlines', () => {
    const wrapped = `\n  ${VeilDisguise.wrapMessage(FAKE_B64)}  \n`;
    expect(VeilDisguise.unwrapMessage(wrapped)).toBe(FAKE_B64);
  });

  it('unwrapMessage returns null for plain text', () => {
    expect(VeilDisguise.unwrapMessage('hello world')).toBeNull();
  });

  it('unwrapMessage returns null for empty string', () => {
    expect(VeilDisguise.unwrapMessage('')).toBeNull();
  });

  it('unwrapMessage returns null when open tag is present but close tag is missing', () => {
    expect(VeilDisguise.unwrapMessage(`${VeilDisguise.TAG_E_OPEN}${FAKE_B64}`)).toBeNull();
  });

  it('unwrapMessage returns null when close tag is present but open tag is missing', () => {
    expect(VeilDisguise.unwrapMessage(`${FAKE_B64}${VeilDisguise.TAG_CLOSE}`)).toBeNull();
  });

  it('unwrapMessage returns null for an H-tagged message', () => {
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64))).toBeNull();
  });

  it('unwrapMessage returns null for a V-tagged message', () => {
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapVerify(FAKE_B64))).toBeNull();
  });

  it('isVeilMessage returns true for an E-tagged string', () => {
    expect(VeilDisguise.isVeilMessage(VeilDisguise.wrapMessage(FAKE_B64))).toBe(true);
  });

  it('isVeilMessage returns false for an H-tagged string', () => {
    expect(VeilDisguise.isVeilMessage(VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64))).toBe(false);
  });

  it('isVeilMessage returns false for a V-tagged string', () => {
    expect(VeilDisguise.isVeilMessage(VeilDisguise.wrapVerify(FAKE_B64))).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('4. Handshake — wrap / unwrap / is', () => {
  const PUB  = btoa('fake-public-key-base64');
  const SIG  = btoa('fake-signature-base64');

  it('wrapHandshake starts with TAG_H_OPEN and ends with TAG_CLOSE', () => {
    const wrapped = VeilDisguise.wrapHandshake(PUB, SIG);
    expect(wrapped.startsWith(VeilDisguise.TAG_H_OPEN)).toBe(true);
    expect(wrapped.endsWith(VeilDisguise.TAG_CLOSE)).toBe(true);
  });

  it('wrapHandshake separates pubKey and sig with exactly one dot', () => {
    const wrapped = VeilDisguise.wrapHandshake(PUB, SIG);
    const inner = wrapped.slice(VeilDisguise.TAG_H_OPEN.length, wrapped.length - VeilDisguise.TAG_CLOSE.length);
    expect(inner).toBe(`${PUB}.${SIG}`);
  });

  it('dot separator is not present in TAG_H_OPEN or TAG_CLOSE', () => {
    expect(VeilDisguise.TAG_H_OPEN).not.toContain('.');
    expect(VeilDisguise.TAG_CLOSE).not.toContain('.');
  });

  it('round-trip: unwrapHandshake(wrapHandshake(pub, sig)) returns correct object', () => {
    const result = VeilDisguise.unwrapHandshake(VeilDisguise.wrapHandshake(PUB, SIG));
    expect(result).toEqual({ publicKey: PUB, signature: SIG });
  });

  it('unwrapHandshake works when the tag appears mid-string', () => {
    const wrapped = `Bob: ${VeilDisguise.wrapHandshake(PUB, SIG)}`;
    expect(VeilDisguise.unwrapHandshake(wrapped)).toEqual({ publicKey: PUB, signature: SIG });
  });

  it('unwrapHandshake slices at first dot — publicKey contains no dot', () => {
    const result = VeilDisguise.unwrapHandshake(VeilDisguise.wrapHandshake(PUB, SIG));
    expect(result?.publicKey).not.toContain('.');
  });

  it('unwrapHandshake returns null for plain text', () => {
    expect(VeilDisguise.unwrapHandshake('hello world')).toBeNull();
  });

  it('unwrapHandshake returns null when close tag is missing', () => {
    expect(VeilDisguise.unwrapHandshake(`${VeilDisguise.TAG_H_OPEN}${PUB}.${SIG}`)).toBeNull();
  });

  it('unwrapHandshake returns null when payload has no dot', () => {
    expect(VeilDisguise.unwrapHandshake(`${VeilDisguise.TAG_H_OPEN}nodothere${VeilDisguise.TAG_CLOSE}`)).toBeNull();
  });

  it('unwrapHandshake returns null for an E-tagged message', () => {
    expect(VeilDisguise.unwrapHandshake(VeilDisguise.wrapMessage(FAKE_B64))).toBeNull();
  });

  it('unwrapHandshake returns null for a V-tagged message', () => {
    expect(VeilDisguise.unwrapHandshake(VeilDisguise.wrapVerify(FAKE_B64))).toBeNull();
  });

  it('isHandshake returns true for an H-tagged string', () => {
    expect(VeilDisguise.isHandshake(VeilDisguise.wrapHandshake(PUB, SIG))).toBe(true);
  });

  it('isHandshake returns false for an E-tagged string', () => {
    expect(VeilDisguise.isHandshake(VeilDisguise.wrapMessage(FAKE_B64))).toBe(false);
  });

  it('isHandshake returns false for a V-tagged string', () => {
    expect(VeilDisguise.isHandshake(VeilDisguise.wrapVerify(FAKE_B64))).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('5. Verify — wrap / unwrap / is', () => {
  it('wrapVerify starts with TAG_V_OPEN and ends with TAG_CLOSE', () => {
    const wrapped = VeilDisguise.wrapVerify(FAKE_B64);
    expect(wrapped.startsWith(VeilDisguise.TAG_V_OPEN)).toBe(true);
    expect(wrapped.endsWith(VeilDisguise.TAG_CLOSE)).toBe(true);
  });

  it('wrapVerify places the payload exactly between the tags', () => {
    const wrapped = VeilDisguise.wrapVerify(FAKE_B64);
    const inner = wrapped.slice(VeilDisguise.TAG_V_OPEN.length, wrapped.length - VeilDisguise.TAG_CLOSE.length);
    expect(inner).toBe(FAKE_B64);
  });

  it('round-trip: unwrapVerify(wrapVerify(x)) === x', () => {
    expect(VeilDisguise.unwrapVerify(VeilDisguise.wrapVerify(FAKE_B64))).toBe(FAKE_B64);
  });

  it('unwrapVerify works when the tag appears mid-string', () => {
    const wrapped = `Carol: ${VeilDisguise.wrapVerify(FAKE_B64)}`;
    expect(VeilDisguise.unwrapVerify(wrapped)).toBe(FAKE_B64);
  });

  it('unwrapVerify returns null for plain text', () => {
    expect(VeilDisguise.unwrapVerify('hello world')).toBeNull();
  });

  it('unwrapVerify returns null when close tag is missing', () => {
    expect(VeilDisguise.unwrapVerify(`${VeilDisguise.TAG_V_OPEN}${FAKE_B64}`)).toBeNull();
  });

  it('unwrapVerify returns null for an E-tagged message', () => {
    expect(VeilDisguise.unwrapVerify(VeilDisguise.wrapMessage(FAKE_B64))).toBeNull();
  });

  it('unwrapVerify returns null for an H-tagged message', () => {
    expect(VeilDisguise.unwrapVerify(VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64))).toBeNull();
  });

  it('isVerifyMessage returns true for a V-tagged string', () => {
    expect(VeilDisguise.isVerifyMessage(VeilDisguise.wrapVerify(FAKE_B64))).toBe(true);
  });

  it('isVerifyMessage returns false for an E-tagged string', () => {
    expect(VeilDisguise.isVerifyMessage(VeilDisguise.wrapMessage(FAKE_B64))).toBe(false);
  });

  it('isVerifyMessage returns false for an H-tagged string', () => {
    expect(VeilDisguise.isVerifyMessage(VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64))).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('6. Type discrimination', () => {
  it('each message type is detected by exactly one is* function', () => {
    const e = VeilDisguise.wrapMessage(FAKE_B64);
    expect(VeilDisguise.isVeilMessage(e)).toBe(true);
    expect(VeilDisguise.isHandshake(e)).toBe(false);
    expect(VeilDisguise.isVerifyMessage(e)).toBe(false);

    const h = VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64);
    expect(VeilDisguise.isVeilMessage(h)).toBe(false);
    expect(VeilDisguise.isHandshake(h)).toBe(true);
    expect(VeilDisguise.isVerifyMessage(h)).toBe(false);

    const v = VeilDisguise.wrapVerify(FAKE_B64);
    expect(VeilDisguise.isVeilMessage(v)).toBe(false);
    expect(VeilDisguise.isHandshake(v)).toBe(false);
    expect(VeilDisguise.isVerifyMessage(v)).toBe(true);
  });

  it('each unwrap function returns null for the other two message types', () => {
    const e = VeilDisguise.wrapMessage(FAKE_B64);
    const h = VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64);
    const v = VeilDisguise.wrapVerify(FAKE_B64);

    // unwrapMessage only works on E
    expect(VeilDisguise.unwrapMessage(h)).toBeNull();
    expect(VeilDisguise.unwrapMessage(v)).toBeNull();

    // unwrapHandshake only works on H
    expect(VeilDisguise.unwrapHandshake(e)).toBeNull();
    expect(VeilDisguise.unwrapHandshake(v)).toBeNull();

    // unwrapVerify only works on V
    expect(VeilDisguise.unwrapVerify(e)).toBeNull();
    expect(VeilDisguise.unwrapVerify(h)).toBeNull();
  });

  it('a string with two different Veil messages is detected by both matching is* functions', () => {
    const combined = VeilDisguise.wrapMessage(FAKE_B64) + ' ' + VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64);
    expect(VeilDisguise.isVeilMessage(combined)).toBe(true);
    expect(VeilDisguise.isHandshake(combined)).toBe(true);
    expect(VeilDisguise.isVerifyMessage(combined)).toBe(false);
  });

  it('isAnyVeil returns true for all three types and false for plain text', () => {
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapMessage(FAKE_B64))).toBe(true);
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapHandshake(FAKE_B64, FAKE_B64))).toBe(true);
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapVerify(FAKE_B64))).toBe(true);
    expect(VeilDisguise.isAnyVeil('plain text')).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('7. Edge cases', () => {
  it('empty payload wraps and unwraps correctly — returns empty string, not null', () => {
    const wrapped = VeilDisguise.wrapMessage('');
    expect(wrapped).toBe(`${VeilDisguise.TAG_E_OPEN}${VeilDisguise.TAG_CLOSE}`);
    expect(VeilDisguise.unwrapMessage(wrapped)).toBe('');
  });

  it('very long payload (2 KB) round-trips correctly', () => {
    const long = btoa('x'.repeat(1500));
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapMessage(long))).toBe(long);
  });

  it('full base64 alphabet in payload does not collide with [/VL] close tag', () => {
    // Base64 uses A-Z a-z 0-9 + / = — the / in the alphabet is not [/VL]
    const result = VeilDisguise.unwrapMessage(VeilDisguise.wrapMessage(FULL_B64_ALPHABET));
    expect(result).toBe(FULL_B64_ALPHABET);
  });

  it('two consecutive E messages in one string — unwrapMessage finds the first one only', () => {
    const first  = VeilDisguise.wrapMessage(btoa('first'));
    const second = VeilDisguise.wrapMessage(btoa('second'));
    const combined = `${first} ${second}`;
    expect(VeilDisguise.unwrapMessage(combined)).toBe(btoa('first'));
  });

  it('payload that is only whitespace is preserved exactly', () => {
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapMessage('   '))).toBe('   ');
  });

  it('handshake with empty publicKey still parses — dot is found, both sides returned', () => {
    const wrapped = `${VeilDisguise.TAG_H_OPEN}.${FAKE_B64}${VeilDisguise.TAG_CLOSE}`;
    expect(VeilDisguise.unwrapHandshake(wrapped)).toEqual({ publicKey: '', signature: FAKE_B64 });
  });
});

// ---------------------------------------------------------------------------

describe('8. Integration with crypto.ts', () => {
  let aesKey: CryptoKey;
  let keyPairA: CryptoKeyPair;
  let keyPairB: CryptoKeyPair;

  beforeAll(async () => {
    keyPairA = await VeilCrypto.generateKeyPair();
    keyPairB = await VeilCrypto.generateKeyPair();
    aesKey = await VeilCrypto.deriveSharedKey(keyPairA.privateKey, keyPairB.publicKey);
  });

  it('encrypt → wrap → unwrap → decrypt returns original plaintext', async () => {
    const plaintext = 'hello from integration test';
    const ciphertext = await VeilCrypto.encrypt(aesKey, plaintext);
    const wrapped    = VeilDisguise.wrapMessage(ciphertext);
    const unwrapped  = VeilDisguise.unwrapMessage(wrapped);
    expect(unwrapped).not.toBeNull();
    const decrypted  = await VeilCrypto.decrypt(aesKey, unwrapped!);
    expect(decrypted).toBe(plaintext);
  });

  it('handshake round-trip: wrap → unwrap → verifyProvenance succeeds', async () => {
    const pubB64 = await VeilCrypto.exportPublicKey(keyPairA);
    const sig    = await VeilCrypto.signProvenance(keyPairA.publicKey);
    const wrapped = VeilDisguise.wrapHandshake(pubB64, sig);
    const data    = VeilDisguise.unwrapHandshake(wrapped);
    expect(data).not.toBeNull();
    const ok = await VeilCrypto.verifyProvenance(
      await VeilCrypto.importPublicKey(data!.publicKey),
      data!.signature,
    );
    expect(ok).toBe(true);
  });

  it('verify round-trip: encrypt fingerprint → wrapVerify → unwrapVerify → decrypt', async () => {
    const pubA = await VeilCrypto.exportPublicKey(keyPairA);
    const pubB = await VeilCrypto.exportPublicKey(keyPairB);
    const fp   = await VeilCrypto.computeFingerprint(pubA, pubB);
    const enc  = await VeilCrypto.encrypt(aesKey, fp);
    const wrapped   = VeilDisguise.wrapVerify(enc);
    const unwrapped = VeilDisguise.unwrapVerify(wrapped);
    expect(unwrapped).not.toBeNull();
    const decrypted = await VeilCrypto.decrypt(aesKey, unwrapped!);
    expect(decrypted).toBe(fp);
  });

  it('ciphertext wrapped as wrong type ([VL:H]) returns null from unwrapMessage', async () => {
    const ciphertext = await VeilCrypto.encrypt(aesKey, 'secret');
    // Manually wrap as handshake type instead of message type
    const wrongWrapped = `${VeilDisguise.TAG_H_OPEN}${ciphertext}${VeilDisguise.TAG_CLOSE}`;
    expect(VeilDisguise.unwrapMessage(wrongWrapped)).toBeNull();
  });

  it('tampered payload inside tag causes VeilCrypto.decrypt to throw', async () => {
    const ciphertext = await VeilCrypto.encrypt(aesKey, 'secret');
    const tampered   = flipByte(ciphertext, 0);
    const wrapped    = VeilDisguise.wrapMessage(tampered);
    const unwrapped  = VeilDisguise.unwrapMessage(wrapped);
    expect(unwrapped).not.toBeNull(); // disguise layer does not detect the tamper
    await expect(VeilCrypto.decrypt(aesKey, unwrapped!)).rejects.toThrow(); // crypto layer does
  });
});
