// Veil Verify — Cloudflare Worker
// Stateless fingerprint relay for out-of-band MITM detection.
//
// Flow:
//   1. Session established → both extensions POST their fingerprint + public key
//   2. Each extension GETs the peer's entry using the peer's public key
//   3. Local comparison: does the peer's claimed fingerprint match mine?
//
// Entries expire after 5 minutes. No database — in-memory Map with TTL.

interface FingerprintEntry {
  fingerprint: string;
  publicKey: string;
  createdAt: number;
}

// In-memory store — survives across requests within the same isolate,
// but NOT across cold starts. That's fine: entries are ephemeral (5 min TTL).
const store = new Map<string, FingerprintEntry>();
const TTL_MS = 5 * 60 * 1000;

function purgeExpired(): void {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (now - entry.createdAt > TTL_MS) {
      store.delete(key);
    }
  }
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

export default {
  async fetch(request: Request): Promise<Response> {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);

    if (url.pathname !== '/verify') {
      return json({ error: 'Not found' }, 404);
    }

    purgeExpired();

    // -----------------------------------------------------------------------
    // POST /verify — publish your fingerprint
    // Body: { publicKey: string, fingerprint: string }
    // -----------------------------------------------------------------------
    if (request.method === 'POST') {
      let body: { publicKey?: string; fingerprint?: string };
      try {
        body = await request.json() as typeof body;
      } catch {
        return json({ error: 'Invalid JSON' }, 400);
      }

      const { publicKey, fingerprint } = body;
      if (!publicKey || !fingerprint) {
        return json({ error: 'Missing publicKey or fingerprint' }, 400);
      }

      // Basic sanity: public key should be base64, fingerprint like "XX-XX-XX-XX"
      if (publicKey.length < 20 || publicKey.length > 500) {
        return json({ error: 'Invalid publicKey length' }, 400);
      }
      if (!/^[A-F0-9]{2}(-[A-F0-9]{2}){3}$/.test(fingerprint)) {
        return json({ error: 'Invalid fingerprint format' }, 400);
      }

      store.set(publicKey, {
        fingerprint,
        publicKey,
        createdAt: Date.now(),
      });

      return json({ ok: true, expiresIn: TTL_MS / 1000 });
    }

    // -----------------------------------------------------------------------
    // GET /verify?publicKey=... — look up a peer's fingerprint
    // -----------------------------------------------------------------------
    if (request.method === 'GET') {
      const publicKey = url.searchParams.get('publicKey');
      if (!publicKey) {
        return json({ error: 'Missing publicKey query param' }, 400);
      }

      const entry = store.get(publicKey);
      if (!entry) {
        return json({ found: false });
      }

      return json({
        found: true,
        fingerprint: entry.fingerprint,
      });
    }

    return json({ error: 'Method not allowed' }, 405);
  },
} satisfies ExportedHandler;
