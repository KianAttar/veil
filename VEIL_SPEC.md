# Veil — Browser Extension Spec
### End-to-End Encryption Layer for Any Web Messenger

---

## Overview

Veil is a Chrome/Chromium extension that adds a transparent layer of end-to-end
encryption over any web-based messenger. Encrypted messages are disguised as
natural-looking text (fake Persian/Arabic prose) so they don't raise suspicion
to observers or automated monitoring systems. Both users must have the extension
installed. The plaintext never leaves the user's browser unencrypted.

---

## Goals

- Encrypt message content before it reaches the messenger platform
- Make ciphertext look like innocent, human-written text
- Work on any website with a text input field
- Be lightweight, dependency-free, and easy to test
- Provide a graceful fallback if auto-send fails

---

## Non-Goals

- Hiding *who* is talking to *whom* (metadata protection)
- Protecting against device-level compromise (keyloggers, screen capture)
- Hiding the fact that the extension is installed
- Working without both users having the extension

---

## Crypto Stack

| Primitive | Algorithm | Purpose |
|---|---|---|
| Key exchange | ECDH P-256 | Derive shared secret from public keys |
| Symmetric encryption | AES-256-GCM | Encrypt/decrypt messages |
| Key derivation | HKDF-SHA256 | Derive AES key from ECDH shared secret |
| Entropy | `window.crypto.getRandomValues` | IV generation |
| API | WebCrypto (`window.crypto.subtle`) | All of the above, built into browser |

No external crypto libraries. Zero dependencies.

---

## Ciphertext Format — v1

Ciphertext is sent as **raw base64** — no wrapping, no disguise in v1.

**Why base64 for v1:**
- All characters (`A-Z a-z 0-9 + / =`) are plain ASCII — every messenger platform
  handles them without mangling, truncating, or re-encoding
- Persian/Arabic Unicode can be silently normalized or reshaped by some platforms,
  which would destroy the ciphertext irreversibly
- Predictable, testable, and easy to debug

**Format:**
```
[prefix_marker][base64_ciphertext][suffix_marker]
```

- Prefix/suffix markers are invisible Unicode zero-width characters used by the
  extension to identify its own messages in the chat
- The ciphertext is: `base64(IV + AES-GCM-tag + encrypted_bytes)`
- To the platform, it looks like a string of random ASCII characters

**v2 — Wrapping (future work):**
Adding a believable container around the base64 (e.g. a forwarded message format)
is a small, isolated change to `disguise.js` and does not affect the crypto layer.
Deliberately deferred — keeping v1 simple and testable.

**Explicitly avoided:** Fake news article snippets or Telegram link previews.
These draw their own attention and are culturally loaded in the Iranian context.

---

## Internationalisation — English & Persian

The extension supports two languages: **English** and **Persian (Farsi)**.

**Language selection:**
- On first launch, before anything else, the user is shown a language picker:
  `English / فارسی`
- Selection is saved to `chrome.storage.local`
- Can be changed at any time from sidebar settings

**Implementation:**
- A single `i18n.js` file holds all UI strings as a plain object:
```javascript
const STRINGS = {
  en: {
    start_session: "Start Secure Session",
    waiting: "Waiting for reply...",
    verified: "Session Verified ✓",
    // ...
  },
  fa: {
    start_session: "شروع گفتگوی امن",
    waiting: "در انتظار پاسخ...",
    verified: "جلسه تأیید شد ✓",
    // ...
  }
}
```
- Persian UI uses RTL layout (`direction: rtl`)
- No external i18n library — just a plain lookup function `t('key')`

---

### Phase 1 — Key Generation
1. User A opens the Veil sidebar
2. User A clicks **"Start Secure Session"**
3. Extension generates an ECDH P-256 keypair for this session
4. Public key is compressed and encoded as a short shareable string (~90 chars)
5. Sidebar displays the invite string with a **Copy** button

### Phase 2 — Handshake
6. User A sends the invite string to User B through the messenger (as a normal message)
7. User B's extension does NOT auto-detect this — User B opens their sidebar,
   sees the invite string in chat, and clicks **"Complete Handshake"** (or pastes it)
8. User B's extension generates its own keypair, derives the shared secret using
   User A's public key, and sends back its own public key as a reply message
9. User A's extension sees the reply, derives the same shared secret
10. Both sides now share the same AES-256-GCM key — session is **established** 🔒

### Phase 3 — Encrypted Messaging
11. User types plaintext in the **Veil sidebar text box**
12. User clicks **Send** (or presses Enter)
13. Extension encrypts the message, disguises it as Arabic-looking text
14. Extension attempts to inject the ciphertext into the messenger's input box and trigger send
15. If injection succeeds → message is sent automatically
16. If injection fails → ciphertext is displayed in the sidebar with a **Copy** button,
    user pastes it manually and sends

### Phase 4 — Decryption
17. Incoming messages are scanned by the extension's content script
18. If a message contains the invisible markers, it is recognized as a Veil message
19. Extension decrypts it and displays the plaintext in the sidebar conversation view
20. The encrypted text in the original messenger remains unchanged (garbled Arabic)

### Phase 5 — Session End
21. Either user can click **"End Session"** in the sidebar
22. All session keys are wiped from memory and `chrome.storage.session`
23. A new handshake is required to resume secure messaging

---

## Input Box Detection — Layered Strategy

The extension uses a three-tier fallback system to locate the active text input:

### Tier 1 — Saved Selector (per domain)
- On first use, if no saved selector exists, onboarding is triggered
- Selector is stored in `chrome.storage.local` keyed by `window.location.hostname`
- On subsequent visits, the saved selector is used directly

### Tier 2 — Focus Detection (auto-detect)
- Extension monitors `focus` events across the page
- When a `textarea` or `[contenteditable]` element is focused, it is stored as
  the candidate input
- Used if no saved selector exists yet and onboarding is skipped

### Tier 3 — Manual Fallback (always available)
- If Tier 1 and Tier 2 both fail to inject, the sidebar shows the ciphertext
  with a **Copy** button
- User manually pastes into the messenger and sends
- Similarly, if an incoming message can't be auto-decrypted in the UI,
  the user can paste ciphertext into the sidebar's **Decrypt** field manually

---

## Onboarding Flow

Triggered once per domain, on first use.

1. Sidebar shows: *"To auto-send encrypted messages, click your chat input box now."*
2. Extension listens for the next click on a `textarea` or `[contenteditable]`
3. A CSS selector is generated and saved for that element
4. Sidebar then asks: *"Now click the Send button."*
5. The send button selector is saved
6. Onboarding complete — never shown again for this domain

Onboarding can be re-triggered from sidebar settings at any time (e.g., if the
messenger changes its layout).

---

## UI — Sidebar

The sidebar is injected as a shadow DOM element to avoid style conflicts with host pages.

### Panels

**Session Panel (no active session)**
```
┌─────────────────────────────┐
│  🔒 VEIL                    │
│                             │
│  No active secure session.  │
│                             │
│  [Start Secure Session]     │
│  [Complete Handshake...]    │
│                             │
│  ─── Manual Tools ────────  │
│  Paste ciphertext to decrypt│
│  [___________________] [Go] │
└─────────────────────────────┘
```

**Handshake Pending Panel**
```
┌─────────────────────────────┐
│  🔒 VEIL — Waiting...       │
│                             │
│  Send this to your contact: │
│  [ECDH public key string  ] │
│  [Copy Invite Code]         │
│                             │
│  Waiting for their reply... │
│  [Cancel]                   │
└─────────────────────────────┘
```

**Active Session Panel**
```
┌─────────────────────────────┐
│  🔒 VEIL — Secure ✓         │
│                             │
│  ┌─────────────────────┐    │
│  │ Them: hello there   │    │
│  │ You: hi!            │    │
│  │ Them: how are you   │    │
│  └─────────────────────┘    │
│                             │
│  [Type your message...    ] │
│  [Send Encrypted]           │
│                             │
│  [End Session]  [Settings]  │
└─────────────────────────────┘
```

---

## Extension File Structure

```
veil-extension/
├── manifest.json          # MV3 manifest
├── content.js             # Injected into every page: DOM scanning, input injection
├── sidebar.html           # Sidebar UI
├── sidebar.js             # Sidebar logic, session state, crypto calls
├── crypto.js              # All WebCrypto operations (shared module)
├── disguise.js            # Encode/decode ciphertext as fake Arabic text
├── background.js          # Service worker: message routing between sidebar & content
└── icons/
    └── icon.png
```

---

## Message Passing Architecture

Chrome extensions have isolated contexts. Communication flows via `chrome.runtime`:

```
sidebar.js  ←→  background.js  ←→  content.js (page)
```

- `sidebar.js` sends commands: `ENCRYPT_AND_SEND`, `DECRYPT_MESSAGE`, `START_SESSION`
- `content.js` handles DOM: `INJECT_TEXT`, `CLICK_SEND`, `SCAN_MESSAGES`
- `background.js` routes messages and holds no persistent state

---

## Storage

| Key | Storage | Contents |
|---|---|---|
| `veil_session_key` | `chrome.storage.session` | AES-GCM CryptoKey (cleared on browser close) |
| `veil_private_key` | `chrome.storage.session` | ECDH private key |
| `veil_input_selector_{hostname}` | `chrome.storage.local` | Saved input box CSS selector |
| `veil_send_selector_{hostname}` | `chrome.storage.local` | Saved send button CSS selector |

Session keys are **never** written to `chrome.storage.local` (not persisted to disk).

---

## Security Properties

| Property | Status |
|---|---|
| Message content confidentiality | ✅ AES-256-GCM |
| Forward secrecy | ✅ Per-session — new keys on every handshake |
| Authentication / tamper detection | ✅ GCM authentication tag |
| Metadata (who/when/how often) | ❌ Not protected |
| MITM during handshake | ✅ Automatic fingerprint verification |
| Fake key from non-Veil source | ✅ HMAC provenance tag |
| Device compromise (malware/spyware) | ❌ Out of scope — no software can protect against this |

---

## What Veil Protects Against

**✅ Protected**
- The messenger platform reading your messages (Telegram, WhatsApp, any web messenger)
- ISPs and network-level deep packet inspection
- Bulk automated keyword scanning of message content
- A third party who gains access to the messenger's database
- Active MITM during the handshake (caught by fingerprint verification)
- Forensic analysis of a closed browser (keys are never written to disk)

**❌ Not Protected**
- Device-level compromise — malware, spyware (e.g. Pegasus), keyloggers
- Physical access to an unlocked, running device with browser open
- A compromised browser (malicious extension with higher privileges)
- User coercion (being forced to decrypt messages)
- Metadata — who is talking to whom, when, and how often remains visible

**The honest summary:** Veil is highly effective against mass surveillance and
platform-level access — the most common threat. It cannot protect against targeted
spyware installed on the device itself. If the device is compromised, no software
can help.

---

## Key Storage — No Persistence Design

This is a deliberate, core design decision:

- Session keys live **only in RAM** via `chrome.storage.session`
- Keys are **never** written to `chrome.storage.local`, `localStorage`, or any disk storage
- Keys are wiped when: the browser closes, the tab closes, or the extension is disabled
- Closing the page = keys are gone = a new handshake is required next time

**Why this matters:** If a device is seized or forensically analyzed after the
browser has been closed, there are no keys to find. The encrypted messages in the
messenger remain unreadable gibberish with no key material on the device.

**Operational hygiene note (shown during onboarding):**
> Close your browser when you are not actively chatting. While the browser is
> open and unlocked, session keys exist in RAM and could theoretically be
> extracted by malware with sufficient privileges.

**To steal the cryptographic keys themselves**, an attacker would need:
- Both devices compromised simultaneously, AND
- Both browsers open and unlocked at the same time

Single-device compromise gives access to plaintext on that device (via screen/memory)
but not the key material needed to decrypt other sessions or impersonate either party.

---

## MITM Protection — Layered Defense

### Layer 1 — HMAC Provenance Tag
Every public key sent during handshake is tagged with an HMAC derived from a
secret baked into the extension at build time.

- Prevents automated systems from injecting valid-looking keys without the extension
- Raises the bar against lazy/automated MITM attacks
- **Limitation:** A determined adversary who reverse-engineers the extension source
  can replicate the tag. Mitigated by open-sourcing the extension so users can
  verify the installed version matches the published source.

### Layer 2 — Automatic Fingerprint Verification
After the handshake, both extensions independently compute:
```
fingerprint = HASH(myPublicKey + theirPublicKey)
```
User A's extension encrypts this fingerprint with the session key and sends it
as a special `VEIL_VERIFY` message. User B's extension decrypts it and compares
it to its own computed fingerprint.

- ✅ Match → session opens, "Verified" shown in sidebar
- ❌ Mismatch → session is blocked, loud warning shown, user told not to proceed

Because the verification message is encrypted with the session key, a MITM cannot
forge it without having already broken the encryption — making the attack circular
and self-defeating.

### Layer 3 — Out-of-Band Verification (optional, recommended for high-risk users)
The sidebar displays a short human-readable fingerprint (e.g. `A3-F7-2C-19`).
Users can compare this over a voice call or in person for maximum assurance.
A "Trust this contact" option saves the fingerprint — if a future handshake
produces a different fingerprint, the extension shows a prominent warning.

---

## Onboarding Checklist (shown on first install)

1. **What Veil does** — one paragraph, plain language
2. **What Veil cannot do** — explicit list of limitations (see above)
3. **Point to your message input box** — click to save selector
4. **Point to your send button** — click to save selector
5. **Operational hygiene reminder** — close browser when not chatting

Onboarding can be re-triggered from sidebar settings at any time.

---

## Testing Strategy

Because the sidebar is plain HTML/JS, it can be opened directly as a file in the
browser (`file:///...sidebar.html`) for UI testing without installing the extension.

Crypto functions in `crypto.js` can be tested in the browser console or in a
simple test page — no build step required.

For full integration testing, load the unpacked extension in Chrome via
`chrome://extensions` → Developer Mode → Load Unpacked.

---

## Resolved Design Decisions

| Decision | Resolution |
|---|---|
| Key persistence | RAM only (`chrome.storage.session`), never disk |
| Forward secrecy | Per-session — new handshake = new keys |
| MITM protection | HMAC provenance tag + automatic fingerprint verification |
| Onboarding | Language pick first, then manual point-and-click, re-triggerable |
| Ciphertext format | Raw base64 wrapped in invisible zero-width markers |
| Ciphertext disguise | Deferred to v2 — base64 is safe on all platforms |
| Input box detection | User points it out (onboarding), with auto-detect + copy-paste fallback |
| UI language | English + Persian, RTL support, chosen on first launch |

## Open Questions / Future Work

- [ ] Should the disguise format use a specific Persian Unicode subset that matches
      common font-rendering artifacts in Persian chat? (More plausible deniability)
- [ ] Should session keys rotate every N messages for stronger forward secrecy?
- [ ] Firefox support (MV3 is supported in Firefox 109+, minor changes needed)
- [ ] Multi-tab support (currently one active session per browser window)
- [ ] Reproducible build process so users can verify installed extension matches source
