# Veil — Claude Instructions

## What this project is
A Chrome extension (MV3) that adds end-to-end encryption to any web messenger.
TypeScript source in `src/`, bundled by esbuild into the extension root.

## Active work plan
See **PLAN.md** — architecture redesign from sidebar to overlay/popup is complete.

## Commands
```bash
pnpm run build        # esbuild: src/ → background.js, content.js, popup.js
pnpm run typecheck    # tsc --noEmit strict check
pnpm run test:unit    # vitest (129 tests across crypto, disguise, i18n)
pnpm run test:e2e     # playwright (requires real browser — not run in CI)
```

## Architecture
```
src/types.ts      shared interfaces (HandshakePayload, ScannedItem, etc.)
src/crypto.ts     WebCrypto: ECDH P-256 + HKDF + AES-256-GCM + HMAC
src/disguise.ts   visible bracket tag wrapping ([VL:I], [VL:R], [VL:E], [VL:V])
src/i18n.ts       English + Persian strings, t(), setLang(), getLang()
src/background.ts service worker — message routing (popup ↔ content), no state
src/content.ts    content script — auto-handshake, MutationObserver, send interception
src/popup.ts      popup panel — session status, start/end session, onboarding trigger
```

## Key design decisions
- Keys live in `chrome.storage.session` (RAM only, never disk)
- `content.js`, `popup.js`, `background.js` in root are esbuild output — not source
- `manifest.json` loads `content.js` as content script; popup.html loads `popup.js`
- Symmetric handshake protocol: nonce-based correlation, timestamp-based stale filtering
- MutationObserver for real-time DOM scanning (replaces polling)
- Send interception at capture phase for transparent encryption
- Playwright E2E tests exist but are excluded from CI (need display server)

## Testing conventions
- Framework: Vitest
- Test files: `test/*.test.ts`
- Style: `describe` groups numbered to match PLAN.md (e.g. `1. Key Generation`)
- Tampering tests use helpers: `flipByte`, `truncate`, `appendBytes`, `prependBytes`
