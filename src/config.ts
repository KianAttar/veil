// Veil — Build-time configuration
// esbuild replaces __VEIL_DEV__ at build time:
//   build      → __VEIL_DEV__ = true  (local dev server)
//   build:prod → __VEIL_DEV__ = false (Cloudflare Worker)

declare const __VEIL_DEV__: boolean;

export const VERIFY_SERVER_URL = __VEIL_DEV__
  ? 'http://localhost:8787'
  : 'https://verify.veil.kiancode.dev';
