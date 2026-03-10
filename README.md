# Veil

A Chrome extension that adds end-to-end encryption to any web messenger — Telegram, WhatsApp, or anything else with a text input box. Both users need the extension installed. The plaintext never leaves your browser unencrypted.

---

## How it works

1. **Alice** clicks *Create Invite*, which generates a one-time ECDH keypair and produces a short invite code
2. **Alice** sends the invite code to Bob through the chat (Veil tries to auto-send it; falls back to copy/paste)
3. **Bob** opens Veil, clicks *I Received an Invite*, pastes the code, and clicks *Connect*
4. Both sides independently derive the same AES-256-GCM key — neither ever sends their private key
5. A fingerprint verification message is exchanged automatically to detect any MITM tampering
6. From this point on, messages typed in the Veil sidebar are encrypted before they touch the messenger

The messenger platform only ever sees base64 ciphertext wrapped in invisible zero-width Unicode markers. The plaintext is shown only inside the Veil sidebar.

---

## Crypto stack

| Layer | Algorithm | Purpose |
|---|---|---|
| Key exchange | ECDH P-256 | Derive shared secret without transmitting private keys |
| Key derivation | HKDF-SHA256 | Turn the raw ECDH output into a proper AES key |
| Encryption | AES-256-GCM | Encrypt messages with authentication |
| Provenance | HMAC-SHA256 | Tag handshake messages as genuine Veil |
| Entropy | `crypto.getRandomValues` | Fresh 96-bit IV per message |

Zero external crypto libraries. Everything runs on the browser's built-in WebCrypto API.

---

## Security properties

| Property | Status |
|---|---|
| Message confidentiality | ✅ AES-256-GCM |
| Integrity / tamper detection | ✅ GCM authentication tag |
| Forward secrecy | ✅ New keys per session |
| MITM detection | ✅ Automatic fingerprint verification |
| Keys at rest | ✅ Never written to disk — session storage only |
| Metadata (who, when, how often) | ❌ Not protected |
| Device-level compromise | ❌ Out of scope |

**The honest summary:** Veil protects against mass surveillance and platform-level access — the most common threat. It cannot protect against targeted spyware on the device itself.

---

## Installation (development)

Veil is not yet on the Chrome Web Store. Load it as an unpacked extension:

```bash
git clone <repo>
cd veil
pnpm install
pnpm run build
```

Then in Chrome:

1. Go to `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the project folder

---

## Development

```bash
pnpm run build          # compile TypeScript → JS (required before loading in Chrome)
pnpm run typecheck      # strict type check without emitting files
pnpm run test:unit      # unit tests (Vitest, ~65 tests)
pnpm run test:e2e       # end-to-end tests (Playwright, requires a display)
```

### Project structure

```
src/
  types.ts        shared TypeScript interfaces
  crypto.ts       all WebCrypto operations
  disguise.ts     zero-width marker wrapping/detection
  i18n.ts         English + Persian strings
  background.ts   service worker — message routing only
  content.ts      injected page script — sidebar, input detection, DOM scanner
  sidebar.ts      sidebar UI and session logic
test/
  crypto.test.ts  unit tests for the crypto module
  veil.spec.ts    end-to-end Playwright tests
```

Source files in `src/` are bundled by esbuild into `background.js`, `content.js`, and `sidebar.js` at the project root. Those three files are what Chrome actually loads.

---

## Languages

The UI supports **English** and **Persian (Farsi)**. Language is chosen on first launch and can be changed in settings. Persian uses RTL layout.

---

## License

MIT — see [LICENSE](LICENSE).
