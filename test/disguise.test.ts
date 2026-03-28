import { describe, it, expect, beforeAll } from 'vitest';
import { VeilDisguise } from '../src/disguise';
import { VeilCrypto } from '../src/crypto';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function decodeBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function flipByte(b64: string, index: number): string {
  const bytes = decodeBase64(b64);
  bytes[index] ^= 0xff;
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

const FAKE_B64 = btoa('this is a fake ciphertext payload for testing');
const FAKE_PUB = btoa('fake-public-key');
const FAKE_SIG = btoa('fake-signature');
const FAKE_NONCE = btoa('testnonce');
const FAKE_TS = 1711468800;
const FULL_B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

// ---------------------------------------------------------------------------

describe('1. Constants', () => {
  it('all five tag constants are non-empty strings', () => {
    for (const tag of [
      VeilDisguise.TAG_I_OPEN,
      VeilDisguise.TAG_R_OPEN,
      VeilDisguise.TAG_E_OPEN,
      VeilDisguise.TAG_V_OPEN,
      VeilDisguise.TAG_CLOSE,
    ]) {
      expect(typeof tag).toBe('string');
      expect(tag.length).toBeGreaterThan(0);
    }
  });

  it('all four open tags are distinct', () => {
    const tags = [
      VeilDisguise.TAG_I_OPEN,
      VeilDisguise.TAG_R_OPEN,
      VeilDisguise.TAG_E_OPEN,
      VeilDisguise.TAG_V_OPEN,
    ];
    expect(new Set(tags).size).toBe(4);
  });

  it('all open tags contain [VL: and close tag is [/VL]', () => {
    for (const tag of [
      VeilDisguise.TAG_I_OPEN,
      VeilDisguise.TAG_R_OPEN,
      VeilDisguise.TAG_E_OPEN,
      VeilDisguise.TAG_V_OPEN,
    ]) {
      expect(tag).toContain('[VL:');
    }
    expect(VeilDisguise.TAG_CLOSE).toBe('[/VL]');
  });
});

// ---------------------------------------------------------------------------

describe('2. isAnyVeil', () => {
  it('returns true for all four message types', () => {
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(true);
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(true);
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapMessage(FAKE_B64))).toBe(true);
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapVerify(FAKE_B64))).toBe(true);
  });

  it('returns false for plain text', () => {
    expect(VeilDisguise.isAnyVeil('hello, how are you?')).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(VeilDisguise.isAnyVeil('')).toBe(false);
  });

  it('is case-sensitive', () => {
    expect(VeilDisguise.isAnyVeil('[vl:i]payload[/vl]')).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('3. Invite — wrap / unwrap / is', () => {
  it('wrapInvite starts with TAG_I_OPEN and ends with TAG_CLOSE', () => {
    const wrapped = VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS);
    expect(wrapped.startsWith(VeilDisguise.TAG_I_OPEN)).toBe(true);
    expect(wrapped.endsWith(VeilDisguise.TAG_CLOSE)).toBe(true);
  });

  it('payload contains four dot-separated fields', () => {
    const wrapped = VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS);
    const inner = wrapped.slice(VeilDisguise.TAG_I_OPEN.length, -VeilDisguise.TAG_CLOSE.length);
    const parts = inner.split('.');
    expect(parts.length).toBe(4);
    expect(parts[0]).toBe(FAKE_PUB);
    expect(parts[1]).toBe(FAKE_SIG);
    expect(parts[2]).toBe(FAKE_NONCE);
    expect(parts[3]).toBe(String(FAKE_TS));
  });

  it('round-trip: unwrapInvite(wrapInvite(...)) returns correct object', () => {
    const result = VeilDisguise.unwrapInvite(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS));
    expect(result).toEqual({ publicKey: FAKE_PUB, signature: FAKE_SIG, nonce: FAKE_NONCE, timestamp: FAKE_TS });
  });

  it('unwrapInvite works when tag appears mid-string', () => {
    const wrapped = `Alice: ${VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS)}`;
    expect(VeilDisguise.unwrapInvite(wrapped)).toEqual({
      publicKey: FAKE_PUB, signature: FAKE_SIG, nonce: FAKE_NONCE, timestamp: FAKE_TS,
    });
  });

  it('unwrapInvite returns null for plain text', () => {
    expect(VeilDisguise.unwrapInvite('hello world')).toBeNull();
  });

  it('unwrapInvite returns null when close tag is missing', () => {
    expect(VeilDisguise.unwrapInvite(`${VeilDisguise.TAG_I_OPEN}${FAKE_PUB}.${FAKE_SIG}.${FAKE_NONCE}.${FAKE_TS}`)).toBeNull();
  });

  it('unwrapInvite returns null when payload has wrong number of fields', () => {
    expect(VeilDisguise.unwrapInvite(`${VeilDisguise.TAG_I_OPEN}only.two${VeilDisguise.TAG_CLOSE}`)).toBeNull();
  });

  it('unwrapInvite returns null when timestamp is not a number', () => {
    expect(VeilDisguise.unwrapInvite(`${VeilDisguise.TAG_I_OPEN}a.b.c.notanumber${VeilDisguise.TAG_CLOSE}`)).toBeNull();
  });

  it('unwrapInvite returns null for a reply-tagged message', () => {
    expect(VeilDisguise.unwrapInvite(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBeNull();
  });

  it('unwrapInvite returns null for an E-tagged message', () => {
    expect(VeilDisguise.unwrapInvite(VeilDisguise.wrapMessage(FAKE_B64))).toBeNull();
  });

  it('isInvite returns true for I-tagged, false for R/E/V', () => {
    expect(VeilDisguise.isInvite(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(true);
    expect(VeilDisguise.isInvite(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(false);
    expect(VeilDisguise.isInvite(VeilDisguise.wrapMessage(FAKE_B64))).toBe(false);
    expect(VeilDisguise.isInvite(VeilDisguise.wrapVerify(FAKE_B64))).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('4. Reply — wrap / unwrap / is', () => {
  it('wrapReply starts with TAG_R_OPEN and ends with TAG_CLOSE', () => {
    const wrapped = VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS);
    expect(wrapped.startsWith(VeilDisguise.TAG_R_OPEN)).toBe(true);
    expect(wrapped.endsWith(VeilDisguise.TAG_CLOSE)).toBe(true);
  });

  it('round-trip: unwrapReply(wrapReply(...)) returns correct object', () => {
    const result = VeilDisguise.unwrapReply(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS));
    expect(result).toEqual({ publicKey: FAKE_PUB, signature: FAKE_SIG, nonce: FAKE_NONCE, timestamp: FAKE_TS });
  });

  it('unwrapReply works when tag appears mid-string', () => {
    const wrapped = `Bob: ${VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS)}`;
    expect(VeilDisguise.unwrapReply(wrapped)?.publicKey).toBe(FAKE_PUB);
  });

  it('unwrapReply returns null for plain text', () => {
    expect(VeilDisguise.unwrapReply('hello world')).toBeNull();
  });

  it('unwrapReply returns null when close tag is missing', () => {
    expect(VeilDisguise.unwrapReply(`${VeilDisguise.TAG_R_OPEN}a.b.c.123`)).toBeNull();
  });

  it('unwrapReply returns null when payload has wrong number of fields', () => {
    expect(VeilDisguise.unwrapReply(`${VeilDisguise.TAG_R_OPEN}one.two.three${VeilDisguise.TAG_CLOSE}`)).toBeNull();
  });

  it('unwrapReply returns null for an invite-tagged message', () => {
    expect(VeilDisguise.unwrapReply(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBeNull();
  });

  it('reply echoes the invite nonce — round-trip verification', () => {
    const inviteNonce = 'abc123nonce';
    const invite = VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, inviteNonce, FAKE_TS);
    const inviteData = VeilDisguise.unwrapInvite(invite)!;

    // Reply echoes the invite's nonce
    const reply = VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, inviteData.nonce, FAKE_TS + 1);
    const replyData = VeilDisguise.unwrapReply(reply)!;

    expect(replyData.nonce).toBe(inviteNonce);
    expect(replyData.nonce).toBe(inviteData.nonce);
  });

  it('isReply returns true for R-tagged, false for I/E/V', () => {
    expect(VeilDisguise.isReply(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(true);
    expect(VeilDisguise.isReply(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(false);
    expect(VeilDisguise.isReply(VeilDisguise.wrapMessage(FAKE_B64))).toBe(false);
    expect(VeilDisguise.isReply(VeilDisguise.wrapVerify(FAKE_B64))).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('5. Encrypted message — wrap / unwrap / is', () => {
  it('wrapMessage starts with TAG_E_OPEN and ends with TAG_CLOSE', () => {
    const wrapped = VeilDisguise.wrapMessage(FAKE_B64);
    expect(wrapped.startsWith(VeilDisguise.TAG_E_OPEN)).toBe(true);
    expect(wrapped.endsWith(VeilDisguise.TAG_CLOSE)).toBe(true);
  });

  it('payload is exactly the base64 string passed in', () => {
    const wrapped = VeilDisguise.wrapMessage(FAKE_B64);
    const inner = wrapped.slice(VeilDisguise.TAG_E_OPEN.length, -VeilDisguise.TAG_CLOSE.length);
    expect(inner).toBe(FAKE_B64);
  });

  it('round-trip: unwrapMessage(wrapMessage(x)) === x', () => {
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapMessage(FAKE_B64))).toBe(FAKE_B64);
  });

  it('unwrapMessage works mid-string', () => {
    expect(VeilDisguise.unwrapMessage(`Alice: ${VeilDisguise.wrapMessage(FAKE_B64)}`)).toBe(FAKE_B64);
  });

  it('unwrapMessage returns null for plain text', () => {
    expect(VeilDisguise.unwrapMessage('hello world')).toBeNull();
  });

  it('unwrapMessage returns null for empty string', () => {
    expect(VeilDisguise.unwrapMessage('')).toBeNull();
  });

  it('unwrapMessage returns null when close tag is missing', () => {
    expect(VeilDisguise.unwrapMessage(`${VeilDisguise.TAG_E_OPEN}${FAKE_B64}`)).toBeNull();
  });

  it('unwrapMessage returns null for I/R/V tagged messages', () => {
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBeNull();
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBeNull();
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapVerify(FAKE_B64))).toBeNull();
  });

  it('isVeilMessage returns true for E-tagged, false for others', () => {
    expect(VeilDisguise.isVeilMessage(VeilDisguise.wrapMessage(FAKE_B64))).toBe(true);
    expect(VeilDisguise.isVeilMessage(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(false);
    expect(VeilDisguise.isVeilMessage(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(false);
    expect(VeilDisguise.isVeilMessage(VeilDisguise.wrapVerify(FAKE_B64))).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('6. Verify — wrap / unwrap / is', () => {
  it('wrapVerify starts with TAG_V_OPEN and ends with TAG_CLOSE', () => {
    const wrapped = VeilDisguise.wrapVerify(FAKE_B64);
    expect(wrapped.startsWith(VeilDisguise.TAG_V_OPEN)).toBe(true);
    expect(wrapped.endsWith(VeilDisguise.TAG_CLOSE)).toBe(true);
  });

  it('round-trip: unwrapVerify(wrapVerify(x)) === x', () => {
    expect(VeilDisguise.unwrapVerify(VeilDisguise.wrapVerify(FAKE_B64))).toBe(FAKE_B64);
  });

  it('unwrapVerify works mid-string', () => {
    expect(VeilDisguise.unwrapVerify(`Carol: ${VeilDisguise.wrapVerify(FAKE_B64)}`)).toBe(FAKE_B64);
  });

  it('unwrapVerify returns null for plain text', () => {
    expect(VeilDisguise.unwrapVerify('hello world')).toBeNull();
  });

  it('unwrapVerify returns null for I/R/E tagged messages', () => {
    expect(VeilDisguise.unwrapVerify(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBeNull();
    expect(VeilDisguise.unwrapVerify(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBeNull();
    expect(VeilDisguise.unwrapVerify(VeilDisguise.wrapMessage(FAKE_B64))).toBeNull();
  });

  it('isVerifyMessage returns true for V-tagged, false for others', () => {
    expect(VeilDisguise.isVerifyMessage(VeilDisguise.wrapVerify(FAKE_B64))).toBe(true);
    expect(VeilDisguise.isVerifyMessage(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(false);
    expect(VeilDisguise.isVerifyMessage(VeilDisguise.wrapMessage(FAKE_B64))).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('7. Type discrimination', () => {
  it('each message type is detected by exactly one is* function', () => {
    const i = VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS);
    const r = VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS);
    const e = VeilDisguise.wrapMessage(FAKE_B64);
    const v = VeilDisguise.wrapVerify(FAKE_B64);

    // Invite: only isInvite
    expect(VeilDisguise.isInvite(i)).toBe(true);
    expect(VeilDisguise.isReply(i)).toBe(false);
    expect(VeilDisguise.isVeilMessage(i)).toBe(false);
    expect(VeilDisguise.isVerifyMessage(i)).toBe(false);

    // Reply: only isReply
    expect(VeilDisguise.isInvite(r)).toBe(false);
    expect(VeilDisguise.isReply(r)).toBe(true);
    expect(VeilDisguise.isVeilMessage(r)).toBe(false);
    expect(VeilDisguise.isVerifyMessage(r)).toBe(false);

    // Encrypted: only isVeilMessage
    expect(VeilDisguise.isInvite(e)).toBe(false);
    expect(VeilDisguise.isReply(e)).toBe(false);
    expect(VeilDisguise.isVeilMessage(e)).toBe(true);
    expect(VeilDisguise.isVerifyMessage(e)).toBe(false);

    // Verify: only isVerifyMessage
    expect(VeilDisguise.isInvite(v)).toBe(false);
    expect(VeilDisguise.isReply(v)).toBe(false);
    expect(VeilDisguise.isVeilMessage(v)).toBe(false);
    expect(VeilDisguise.isVerifyMessage(v)).toBe(true);
  });

  it('each unwrap function returns null for all other types', () => {
    const i = VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS);
    const r = VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS);
    const e = VeilDisguise.wrapMessage(FAKE_B64);
    const v = VeilDisguise.wrapVerify(FAKE_B64);

    // unwrapInvite only works on I
    expect(VeilDisguise.unwrapInvite(r)).toBeNull();
    expect(VeilDisguise.unwrapInvite(e)).toBeNull();
    expect(VeilDisguise.unwrapInvite(v)).toBeNull();

    // unwrapReply only works on R
    expect(VeilDisguise.unwrapReply(i)).toBeNull();
    expect(VeilDisguise.unwrapReply(e)).toBeNull();
    expect(VeilDisguise.unwrapReply(v)).toBeNull();

    // unwrapMessage only works on E
    expect(VeilDisguise.unwrapMessage(i)).toBeNull();
    expect(VeilDisguise.unwrapMessage(r)).toBeNull();
    expect(VeilDisguise.unwrapMessage(v)).toBeNull();

    // unwrapVerify only works on V
    expect(VeilDisguise.unwrapVerify(i)).toBeNull();
    expect(VeilDisguise.unwrapVerify(r)).toBeNull();
    expect(VeilDisguise.unwrapVerify(e)).toBeNull();
  });

  it('a string with two different Veil messages is detected by both matching is* functions', () => {
    const combined = VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS)
      + ' ' + VeilDisguise.wrapMessage(FAKE_B64);
    expect(VeilDisguise.isInvite(combined)).toBe(true);
    expect(VeilDisguise.isVeilMessage(combined)).toBe(true);
    expect(VeilDisguise.isReply(combined)).toBe(false);
    expect(VeilDisguise.isVerifyMessage(combined)).toBe(false);
  });

  it('isAnyVeil returns true for all four types and false for plain text', () => {
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(true);
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapReply(FAKE_PUB, FAKE_SIG, FAKE_NONCE, FAKE_TS))).toBe(true);
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapMessage(FAKE_B64))).toBe(true);
    expect(VeilDisguise.isAnyVeil(VeilDisguise.wrapVerify(FAKE_B64))).toBe(true);
    expect(VeilDisguise.isAnyVeil('plain text')).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('8. Edge cases', () => {
  it('empty ciphertext wraps and unwraps correctly', () => {
    const wrapped = VeilDisguise.wrapMessage('');
    expect(VeilDisguise.unwrapMessage(wrapped)).toBe('');
  });

  it('very long payload (2 KB) round-trips correctly', () => {
    const long = btoa('x'.repeat(1500));
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapMessage(long))).toBe(long);
  });

  it('full base64 alphabet in payload does not collide with [/VL]', () => {
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapMessage(FULL_B64_ALPHABET))).toBe(FULL_B64_ALPHABET);
  });

  it('two consecutive E messages — unwrapMessage finds the first', () => {
    const first = VeilDisguise.wrapMessage(btoa('first'));
    const second = VeilDisguise.wrapMessage(btoa('second'));
    expect(VeilDisguise.unwrapMessage(`${first} ${second}`)).toBe(btoa('first'));
  });

  it('whitespace-only payload is preserved', () => {
    expect(VeilDisguise.unwrapMessage(VeilDisguise.wrapMessage('   '))).toBe('   ');
  });

  it('timestamp 0 is valid', () => {
    const result = VeilDisguise.unwrapInvite(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, 0));
    expect(result?.timestamp).toBe(0);
  });

  it('very large timestamp is preserved', () => {
    const bigTs = 9999999999;
    const result = VeilDisguise.unwrapInvite(VeilDisguise.wrapInvite(FAKE_PUB, FAKE_SIG, FAKE_NONCE, bigTs));
    expect(result?.timestamp).toBe(bigTs);
  });

  it('invite and reply with same nonce can be correlated', () => {
    const nonce = 'session42';
    const invite = VeilDisguise.unwrapInvite(VeilDisguise.wrapInvite('pubA', 'sigA', nonce, 1000))!;
    const reply = VeilDisguise.unwrapReply(VeilDisguise.wrapReply('pubB', 'sigB', nonce, 1005))!;
    expect(invite.nonce).toBe(reply.nonce);
    expect(invite.publicKey).not.toBe(reply.publicKey);
    expect(reply.timestamp).toBeGreaterThan(invite.timestamp);
  });
});

// ---------------------------------------------------------------------------

describe('9. Handshake protocol simulation', () => {
  it('full invite → reply → verify flow with nonce correlation', () => {
    const nonceA = 'randomNonce123';
    const tsA = Math.floor(Date.now() / 1000);

    // Alice sends invite
    const invite = VeilDisguise.wrapInvite('pubA', 'sigA', nonceA, tsA);
    expect(VeilDisguise.isInvite(invite)).toBe(true);

    // Bob sees the invite, extracts nonce
    const inviteData = VeilDisguise.unwrapInvite(invite)!;
    expect(inviteData.nonce).toBe(nonceA);

    // Bob sends reply, echoing Alice's nonce
    const reply = VeilDisguise.wrapReply('pubB', 'sigB', inviteData.nonce, tsA + 2);
    expect(VeilDisguise.isReply(reply)).toBe(true);

    // Alice sees the reply, confirms nonce match
    const replyData = VeilDisguise.unwrapReply(reply)!;
    expect(replyData.nonce).toBe(nonceA);

    // Both send verify messages
    const verifyA = VeilDisguise.wrapVerify('encryptedFpA');
    const verifyB = VeilDisguise.wrapVerify('encryptedFpB');
    expect(VeilDisguise.unwrapVerify(verifyA)).toBe('encryptedFpA');
    expect(VeilDisguise.unwrapVerify(verifyB)).toBe('encryptedFpB');
  });

  it('old invite is distinguishable from new invite by timestamp', () => {
    const oldInvite = VeilDisguise.wrapInvite('pubOld', 'sigOld', 'nonceOld', 1000);
    const newInvite = VeilDisguise.wrapInvite('pubNew', 'sigNew', 'nonceNew', 2000);

    const oldData = VeilDisguise.unwrapInvite(oldInvite)!;
    const newData = VeilDisguise.unwrapInvite(newInvite)!;

    expect(newData.timestamp).toBeGreaterThan(oldData.timestamp);
    // Content script would filter: if oldData.timestamp < sessionEstablishedAt → skip
  });

  it('reply with wrong nonce does not match initiator', () => {
    const myNonce = 'myNonce123';
    const reply = VeilDisguise.wrapReply('pubB', 'sigB', 'differentNonce', 2000);
    const replyData = VeilDisguise.unwrapReply(reply)!;
    expect(replyData.nonce).not.toBe(myNonce);
  });

  it('simultaneous invites have different nonces', () => {
    const inviteA = VeilDisguise.wrapInvite('pubA', 'sigA', 'nonceA', 1000);
    const inviteB = VeilDisguise.wrapInvite('pubB', 'sigB', 'nonceB', 1000);

    const dataA = VeilDisguise.unwrapInvite(inviteA)!;
    const dataB = VeilDisguise.unwrapInvite(inviteB)!;

    // Same timestamp (simultaneous) but different nonces
    expect(dataA.timestamp).toBe(dataB.timestamp);
    expect(dataA.nonce).not.toBe(dataB.nonce);
    expect(dataA.publicKey).not.toBe(dataB.publicKey);
  });
});

// ---------------------------------------------------------------------------

describe('10. Integration with crypto.ts', () => {
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
    const wrapped = VeilDisguise.wrapMessage(ciphertext);
    const unwrapped = VeilDisguise.unwrapMessage(wrapped);
    expect(unwrapped).not.toBeNull();
    const decrypted = await VeilCrypto.decrypt(aesKey, unwrapped!);
    expect(decrypted).toBe(plaintext);
  });

  it('invite round-trip with real keys: wrap → unwrap → verifyProvenance', async () => {
    const pubB64 = await VeilCrypto.exportPublicKey(keyPairA);
    const sig = await VeilCrypto.signProvenance(keyPairA.publicKey);
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(8))));
    const ts = Math.floor(Date.now() / 1000);

    const wrapped = VeilDisguise.wrapInvite(pubB64, sig, nonce, ts);
    const data = VeilDisguise.unwrapInvite(wrapped)!;

    expect(data.publicKey).toBe(pubB64);
    expect(data.nonce).toBe(nonce);
    expect(data.timestamp).toBe(ts);

    const ok = await VeilCrypto.verifyProvenance(
      await VeilCrypto.importPublicKey(data.publicKey),
      data.signature,
    );
    expect(ok).toBe(true);
  });

  it('verify round-trip: encrypt fingerprint → wrapVerify → unwrapVerify → decrypt', async () => {
    const pubA = await VeilCrypto.exportPublicKey(keyPairA);
    const pubB = await VeilCrypto.exportPublicKey(keyPairB);
    const fp = await VeilCrypto.computeFingerprint(pubA, pubB);
    const enc = await VeilCrypto.encrypt(aesKey, fp);
    const wrapped = VeilDisguise.wrapVerify(enc);
    const unwrapped = VeilDisguise.unwrapVerify(wrapped)!;
    const decrypted = await VeilCrypto.decrypt(aesKey, unwrapped);
    expect(decrypted).toBe(fp);
  });

  it('tampered payload inside tag causes VeilCrypto.decrypt to throw', async () => {
    const ciphertext = await VeilCrypto.encrypt(aesKey, 'secret');
    const tampered = flipByte(ciphertext, 0);
    const wrapped = VeilDisguise.wrapMessage(tampered);
    const unwrapped = VeilDisguise.unwrapMessage(wrapped)!;
    await expect(VeilCrypto.decrypt(aesKey, unwrapped)).rejects.toThrow();
  });

  it('full handshake simulation: invite → reply → derive same key → encrypted message', async () => {
    // Alice generates keypair
    const aliceKP = await VeilCrypto.generateKeyPair();
    const alicePub = await VeilCrypto.exportPublicKey(aliceKP);
    const aliceSig = await VeilCrypto.signProvenance(aliceKP.publicKey);
    const nonce = 'testNonce';
    const ts = Math.floor(Date.now() / 1000);

    // Alice sends invite
    const invite = VeilDisguise.wrapInvite(alicePub, aliceSig, nonce, ts);

    // Bob receives, unwraps, verifies
    const inviteData = VeilDisguise.unwrapInvite(invite)!;
    const aliceKey = await VeilCrypto.importPublicKey(inviteData.publicKey);
    expect(await VeilCrypto.verifyProvenance(aliceKey, inviteData.signature)).toBe(true);

    // Bob generates keypair, derives shared key
    const bobKP = await VeilCrypto.generateKeyPair();
    const bobPub = await VeilCrypto.exportPublicKey(bobKP);
    const bobSig = await VeilCrypto.signProvenance(bobKP.publicKey);
    const bobKey = await VeilCrypto.deriveSharedKey(bobKP.privateKey, aliceKey);

    // Bob sends reply echoing nonce
    const reply = VeilDisguise.wrapReply(bobPub, bobSig, inviteData.nonce, ts + 1);

    // Alice receives reply, derives shared key
    const replyData = VeilDisguise.unwrapReply(reply)!;
    expect(replyData.nonce).toBe(nonce); // nonce matches
    const bobImported = await VeilCrypto.importPublicKey(replyData.publicKey);
    const aliceSharedKey = await VeilCrypto.deriveSharedKey(aliceKP.privateKey, bobImported);

    // Both keys should produce matching encrypt/decrypt
    const encrypted = await VeilCrypto.encrypt(bobKey, 'secret message');
    const wrapped = VeilDisguise.wrapMessage(encrypted);
    const unwrapped = VeilDisguise.unwrapMessage(wrapped)!;
    const decrypted = await VeilCrypto.decrypt(aliceSharedKey, unwrapped);
    expect(decrypted).toBe('secret message');
  });
});
