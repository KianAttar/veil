# Veil — Study & Test Plan

Working through the codebase bottom-up: understand each file, then write
unit tests for it before moving to the next layer.

---

## Dependency Hierarchy (bottom → top)

```
src/types.ts        ← pure type definitions, no logic
src/crypto.ts       ← no Veil dependencies, just WebCrypto        ✅ DONE
src/disguise.ts     ← imports types.ts                              ✅ DONE
src/i18n.ts         ← imports types.ts
src/background.ts   ← no Veil dependencies, just Chrome APIs
src/content.ts      ← imports crypto + disguise
src/sidebar.ts      ← imports crypto + disguise + i18n             (top)
```

---

## Progress

### ✅ src/crypto.ts — DONE
- Walkthrough: ECDH P-256, HKDF, AES-256-GCM, HMAC provenance, fingerprint
- Tests: `test/crypto.test.ts` — 65 tests, all passing
- Topics covered: key generation, export/import round-trips, shared key
  derivation, encrypt/decrypt output properties, 16 tampering scenarios,
  fingerprint MITM detection, HMAC sign/verify, utility encoding

---

### ✅ src/disguise.ts — DONE
- Redesigned from zero-width Unicode markers to visible bracket tags [VL:E/H/V]...[/VL]
- wrap/unwrap for messages, handshakes, and verify messages
- isAnyVeil / isVeilMessage / isHandshake / isVerifyMessage detection logic
- Dropped fallback parser (visible tags are never stripped by messengers)
- Tests: `test/disguise.test.ts` — 63 tests, all passing
- Topics covered: constants, isAnyVeil, wrap/unwrap round-trips, type
  discrimination, edge cases, integration with VeilCrypto

### ⬜ src/i18n.ts — NEXT
- STRINGS object structure (en + fa)
- `t(key)` lookup with fallback chain
- `setLang` / `getLang` module state
- Tests: key lookup, missing key fallback, language switching, all keys
  present in both languages

### ⬜ src/background.ts
- Chrome action click → TOGGLE_SIDEBAR message routing
- Message forwarding: sidebar → content script (target: 'content')
- GET_TAB_HOSTNAME handler
- Note: Chrome APIs make this harder to unit test — likely light coverage
  or integration-only

### ⬜ src/content.ts
- Sidebar DOM injection and layout (push vs overlay)
- Focus detection (Tier 2 input detection)
- Onboarding click capture and CSS selector generation
- Input injection (contenteditable vs value-based inputs)
- DOM message scanner (TreeWalker + 2s interval)
- Message passing with sidebar (postMessage)
- Tests: selector generation, injection logic, scanner detection

### ⬜ src/sidebar.ts
- Session state machine (panelLang → panelNoSession → panelHandshake →
  panelSession)
- Full handshake flow: startSession, acceptHandshake, completeHandshakeAsInitiator
- Fingerprint verification handler
- Message encrypt/send and decrypt/display
- Manual decrypt fallback
- Onboarding flow
- Tests: panel transitions, handshake state, message rendering, fallback logic
