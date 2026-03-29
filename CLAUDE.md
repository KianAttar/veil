# Veil — Claude Instructions

## What this project is
A Chrome extension (MV3) that adds end-to-end encryption to any web messenger.
TypeScript source in `src/`, bundled by esbuild into the extension root.

## Active work plan
See **PLAN.md** — architecture redesign from sidebar to overlay/popup is complete.

## Commands
```bash
pnpm run build        # esbuild: src/ → background.js, content.js, popup.js
pnpm run build:prod   # production build with --drop:console
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
src/config.ts     environment config (verify server URL)
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
- Production build strips all console.* calls via esbuild `--drop:console`

## Testing conventions
- Framework: Vitest
- Test files: `test/*.test.ts`
- Style: `describe` groups numbered to match PLAN.md (e.g. `1. Key Generation`)
- Tampering tests use helpers: `flipByte`, `truncate`, `appendBytes`, `prependBytes`

## Deployment & infrastructure
- **GitHub repo**: github.com/KianAttar/veil
- **Branches**: `dev` (working branch), `main` (production — triggers Pages deploy)
- **Landing page**: `docs/index.html` → deployed to `veil.kiancode.dev` via GitHub Pages
  - Source: `docs/` directory on `main` branch
  - Custom domain configured via `docs/CNAME`
  - GitHub Actions workflow: `.github/workflows/pages.yml`
  - Sections: hero, how it works, demo, security, verification, privacy
  - Hamburger nav on mobile
- **Privacy policy**: `docs/privacy.html`
- **Verify server**: Cloudflare Worker at `verify.veil.kiancode.dev`
  - Source: `verify-server/` directory (Wrangler project)
  - Used for out-of-band session fingerprint verification

## Demo pages (docs/demo/)
- **Tutorial** (`docs/demo/index.html`): 7-step guided walkthrough with side-by-side Bob & John panels. All content is pre-scripted (no real crypto). Steps: The Problem → Bob Starts Veil → Key Exchange → Encrypted Chat → Server View → Keys Lost → CTA. Navigated with Next/Previous buttons and arrow keys. Responsive (panels stack on mobile).
- **Chat playground** (`docs/demo/chat/index.html`): Simple real chat between two tabs via BroadcastChannel. User picks Bob or John (?u=bob / ?u=john). Messages are plain text — designed for testing with the real Veil extension installed. localStorage for message persistence, sessionStorage not used.

## Chrome Web Store
- **Listing text**: `chrome-store/listing.md`
- **Privacy form answers**: `chrome-store/privacy-form.md`
- **Screenshots HTML template**: `chrome-store/screenshots.html`
- **Promo tile template**: `chrome-store/promo.html`
- **Production zip**: `chrome-store/veil-extension.zip` (rebuild with `pnpm run build:prod` then re-zip)
- **Icons**: `icons/icon.svg` (shield+V source), `icons/icon48.png`, `icons/icon128.png`
  - Convert SVG to PNG: `rsvg-convert -w 48 icons/icon.svg > icons/icon48.png`
- Permissions requested: `storage`, `activeTab`, `scripting` — all justified in privacy form
