# Veil — Claude Instructions

## What this project is
A Chrome extension (MV3) that adds end-to-end encryption to any web messenger.
TypeScript source in `src/`, bundled by esbuild into the extension root.

## Active work plan
See **PLAN.md** — we are working through the codebase bottom-up (explain +
unit test each file). `src/crypto.ts` is done. Next is `src/disguise.ts`.

## Commands
```bash
pnpm run build        # esbuild: src/ → background.js, content.js, sidebar.js
pnpm run typecheck    # tsc --noEmit strict check
pnpm run test:unit    # vitest (65 tests, all in test/crypto.test.ts so far)
pnpm run test:e2e     # playwright (requires real browser — not run in CI)
```

## Architecture
```
src/types.ts      shared interfaces (HandshakeData, ScannedItem, etc.)
src/crypto.ts     WebCrypto: ECDH P-256 + HKDF + AES-256-GCM + HMAC
src/disguise.ts   zero-width marker wrapping (messages, handshakes, verify)
src/i18n.ts       English + Persian strings, t(), setLang(), getLang()
src/background.ts service worker — message routing only, no state
src/content.ts    injected page script — sidebar DOM, input detection, scanner
src/sidebar.ts    sidebar UI — session state machine, crypto calls, panels
```

## Key design decisions
- Keys live in `chrome.storage.session` (RAM only, never disk)
- `content.js`, `sidebar.js`, `background.js` in root are esbuild output — not source
- `manifest.json` loads only `content.js`; sidebar.html loads only `sidebar.js`
- Playwright E2E tests exist but are excluded from CI (need display server)

## Testing conventions
- Framework: Vitest
- Test files: `test/*.test.ts`
- Style: `describe` groups numbered to match PLAN.md (e.g. `1. Key Generation`)
- Tampering tests use helpers: `flipByte`, `truncate`, `appendBytes`, `prependBytes`
