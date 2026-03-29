# Chrome Web Store — Privacy Form Answers

## Single Purpose

### Single purpose description

Veil encrypts and decrypts chat messages directly in the browser using end-to-end encryption (ECDH key exchange + AES-256-GCM), so that the messaging platform only sees ciphertext. It works on any web messenger by intercepting outgoing messages, encrypting them before they are sent, and decrypting incoming encrypted messages in-place.

---

## Permission Justification

### storage

Veil uses chrome.storage.local to persist two types of user preferences: (1) the selected interface language (English or Persian), and (2) per-site CSS selectors for the chat input box and send button, detected during one-time setup. Veil uses chrome.storage.session (RAM-only, never written to disk) to hold ephemeral encryption keys for the active session. No user content or messages are stored.

### activeTab

Veil needs access to the active tab's DOM to perform its core function: scanning chat messages for encrypted payloads, decrypting them and displaying the plaintext as annotations, and intercepting outgoing messages to encrypt them before they are sent. Without activeTab, the extension cannot read or modify the page content where the chat is displayed.

### tabs

Veil uses the tabs permission in its background service worker to identify the active tab's URL when routing messages between the popup panel and the content script. The popup sends commands (start session, end session) to the background, which must look up the correct tab by URL to forward the message. Only the hostname is used, to match per-site configuration. No browsing history is collected or stored.

### Host permission (<all_urls>)

Veil injects a content script on all URLs because it is designed to work on any web messenger — WhatsApp Web, Telegram Web, Facebook Messenger, Signal Desktop, and any other chat that runs in the browser. The extension cannot predict which domains the user will use for messaging, so it must be available on all pages. The content script only activates its encryption functionality when the user explicitly starts a session. On pages without an active session, the content script performs no DOM modifications and no data processing.

---

## Remote Code

**No, I am not using remote code.**

All JavaScript is bundled at build time using esbuild. No external scripts, no eval(), no dynamic imports. The only network request the extension makes is an optional HTTPS POST/GET to a Cloudflare Worker (verify.veil.kiancode.dev) to exchange public key fingerprints for man-in-the-middle detection. This request sends only a SHA-256 hash of the session's public key — no user data, no message content, no identifiers.

---

## Data Usage

### What user data do you plan to collect?

**None.** No checkboxes should be selected.

Veil does not collect, store, or transmit any of the following:

- ✗ Personally identifiable information
- ✗ Health information
- ✗ Financial and payment information
- ✗ Authentication information
- ✗ Personal communications (messages are encrypted/decrypted locally and never leave the browser in plaintext)
- ✗ Location
- ✗ Web history
- ✗ User activity
- ✗ Website content

### Certifications

All three should be checked:

- ✓ I do not sell or transfer user data to third parties, outside of the approved use cases
- ✓ I do not use or transfer user data for purposes that are unrelated to my item's single purpose
- ✓ I do not use or transfer user data to determine creditworthiness or for lending purposes

---

## Privacy Policy

### Privacy Policy URL

`https://veil.kiancode.dev/privacy.html`

> **Note:** This page needs to be created. See below for the content.

---

## Privacy Policy Content (for privacy.html)

**Privacy Policy — Veil Browser Extension**

Last updated: March 28, 2026

Veil is a browser extension that provides end-to-end encryption for web-based chat messengers. This policy explains what data Veil handles and how.

**Data Veil does NOT collect:**

- No personal information (name, email, phone, etc.)
- No message content — all encryption and decryption happens locally in your browser
- No browsing history or web activity
- No analytics, telemetry, or usage tracking
- No cookies or third-party tracking

**Data stored locally on your device:**

- Language preference (English or Persian)
- Per-site CSS selectors for input detection (stored in chrome.storage.local)
- Session encryption keys (stored in chrome.storage.session — RAM only, erased when the browser closes)

**Network requests:**
Veil makes one optional network request per session to a verification server (verify.veil.kiancode.dev) to detect man-in-the-middle attacks. This request contains only a SHA-256 hash of the session's public key. No user data, message content, or identifying information is transmitted.

**Third parties:**
Veil does not share any data with third parties. There are no ads, no analytics services, and no data brokers.

**Open source:**
Veil's complete source code is available at https://github.com/KianAttar/veil. You can audit exactly what the extension does.

**Disclaimer:**
Veil is provided "as is", without warranty of any kind, express or implied. The author is not liable for any damages, data loss, or security incidents arising from the use of this software. Veil is free, open-source software distributed under the MIT License, which contains the full warranty disclaimer. Veil is a security tool, not a guarantee of security. Users are responsible for verifying session fingerprints and understanding the limitations described on the home page.

**Changes to this policy:**
If this policy is updated, the changes will be posted on this page with an updated date. Continued use of the extension after changes constitutes acceptance.

**Contact:**
support@kiancode.dev

## Additional instructions:

No login required. To test:

1. Install the extension and open any webpage
2. Click the Veil icon in the toolbar
3. Click "Set up for this site" and click an input box, then a send button
4. Open the same page in a second tab
5. Click "Start Session" in both tabs — they will exchange keys automatically
6. Type a message — it will be encrypted before sending
