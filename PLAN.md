# Veil — Study & Test Plan

Working through the codebase bottom-up: understand each file, then write
unit tests for it before moving to the next layer.

---

## Dependency Hierarchy (bottom → top)

```
src/types.ts        ← pure type definitions, no logic
src/crypto.ts       ← no Veil dependencies, just WebCrypto        ✅ DONE
src/disguise.ts     ← imports types.ts                              ✅ DONE
src/i18n.ts         ← imports types.ts                              ✅ DONE
src/background.ts   ← popup ↔ content routing, Chrome APIs          ✅ DONE
src/content.ts      ← imports crypto + disguise                      ✅ DONE
src/popup.ts        ← reads session state, sends commands            ✅ DONE
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
- Redesigned to visible bracket tags: [VL:I] invite, [VL:R] reply, [VL:E] encrypted, [VL:V] verify
- Nonce + timestamp fields in handshake payloads for symmetric protocol
- wrap/unwrap for invites, replies, messages, and verify messages
- isAnyVeil / isVeilMessage / isInvite / isReply / isVerifyMessage detection
- Tests: `test/disguise.test.ts` — 63 tests, all passing

### ✅ src/i18n.ts — DONE
- Simple lookup table — no logic warranting deep testing
- Exported STRINGS to allow direct key comparison in tests
- Tests: `test/i18n.test.ts` — 1 test: every English key is present in Persian

### ✅ src/background.ts — DONE
- Simplified from sidebar routing to popup ↔ content routing
- Routes `target: 'content'` messages from popup to active tab
- GET_TAB_HOSTNAME handler for popup hostname display
- Removed: TOGGLE_SIDEBAR, sidebar forwarding

### ✅ src/content.ts — DONE (v2: overlay architecture)
- Complete rewrite from sidebar-based to overlay-based architecture
- Symmetric auto-handshake: nonce-based invite/reply correlation
- Timestamp filtering: ignores handshake messages older than 10 minutes
- MutationObserver for real-time DOM scanning (replaces 2s polling)
- DOM text replacement: decrypted messages replace ciphertext inline
- Send interception: captures Enter key, encrypts, replaces input text
- "Veil: ON/OFF" toggle badge near chat input
- Onboarding: input event detection + click capture for send button
- Toast notifications for status feedback

### ✅ src/popup.ts — DONE
- Popup panel replacing old sidebar UI
- Reads session state from chrome.storage.session
- Buttons: Start Session, End Session, Set up for this site, Re-configure
- Language toggle (English / Persian)
- Enforces onboarding-first: Start Session disabled until selectors saved

---

## Architecture Redesign (v2)

### What changed
- **Sidebar → Popup panel**: Settings/session control moved to Chrome action popup
- **DOM text replacement**: Decrypted messages shown inline (not in separate UI)
- **MutationObserver**: Real-time scanning replaces 2-second polling
- **Auto-handshake**: No manual copy/paste — nonce-based symmetric protocol
- **Send interception**: Transparent encryption via capture-phase event listeners
- **sidebar.ts / sidebar.html deleted**: No longer part of the extension
