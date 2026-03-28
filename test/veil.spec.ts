import { test, expect, chromium, BrowserContext, Page } from '@playwright/test';
import path from 'path';
import http from 'http';
import fs from 'fs';

const EXT_PATH = path.resolve(__dirname, '..');
const CHAT_PAGE = path.resolve(__dirname, 'chat-page.html');

let server: http.Server;
let serverUrl: string;

function startServer(): Promise<void> {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      fs.createReadStream(CHAT_PAGE).pipe(res);
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      serverUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
}

function stopServer(): Promise<void> {
  return new Promise((resolve) => {
    if (server) server.close(() => resolve());
    else resolve();
  });
}

function launchBrowser(): Promise<BrowserContext> {
  return chromium.launchPersistentContext('', {
    headless: false,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      '--no-first-run',
      '--disable-search-engine-choice-screen',
    ],
  });
}

/** Get the service worker so we can send messages to the content script. */
async function getServiceWorker(context: BrowserContext) {
  let sw = context.serviceWorkers().find((w) => w.url().includes('background.js'));
  if (!sw) {
    sw = await context.waitForEvent('serviceworker', {
      predicate: (w) => w.url().includes('background.js'),
      timeout: 10000,
    });
  }
  return sw;
}

/** Send a message to the content script via the background service worker. */
async function sendToContent(context: BrowserContext, msg: Record<string, unknown>) {
  const sw = await getServiceWorker(context);
  return sw.evaluate((m) => {
    return new Promise<unknown>((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].id !== undefined) {
          chrome.tabs.sendMessage(tabs[0].id, m, (resp) => resolve(resp));
        } else {
          resolve(null);
        }
      });
    });
  }, msg);
}

/**
 * Perform onboarding for a browser context:
 * 1. Send START_ONBOARDING to content
 * 2. Type in chat input (triggers input detection)
 * 3. Click send button (triggers send button detection)
 */
async function doOnboarding(page: Page, context: BrowserContext): Promise<void> {
  await sendToContent(context, { type: 'START_ONBOARDING' });
  await page.waitForTimeout(300);

  // Step 1: Type in the chat input to trigger input detection
  await page.fill('#chatInput', 'test');
  await page.waitForTimeout(500);

  // Step 2: Click the send button to trigger send button detection
  await page.click('#sendBtn');
  await page.waitForTimeout(500);
}

/**
 * Inject a message into the chat DOM and trigger content script scan.
 * In real usage, MutationObserver handles this automatically when messages
 * arrive via the page's own JS. In Playwright tests, we need to trigger
 * a manual scan because page.evaluate runs in a different JS world.
 */
async function injectAndScan(page: Page, context: BrowserContext, text: string): Promise<void> {
  await page.evaluate((t) => {
    const div = document.createElement('div');
    div.className = 'message';
    div.appendChild(document.createTextNode(t));
    document.getElementById('messages')!.appendChild(div);
  }, text);
  await page.waitForTimeout(200);
  await sendToContent(context, { type: 'DEBUG_SCAN' });
  await page.waitForTimeout(500);
}

/** Get Veil payload text from a chat message (skip sender span). */
async function getVeilPayloads(page: Page): Promise<string[]> {
  return page.$$eval('#messages .message', (els) => {
    return els.map((el) => {
      const texts: string[] = [];
      el.childNodes.forEach((n) => {
        if (n.nodeType === Node.TEXT_NODE && n.textContent) {
          texts.push(n.textContent);
        }
      });
      return texts.join('');
    }).filter((t) => t.includes('[VL:'));
  });
}

/** Get text content of all messages in the chat. */
async function getChatMessages(page: Page): Promise<string[]> {
  return page.$$eval('#messages .message', (els) =>
    els.map((el) => el.textContent ?? ''),
  );
}

/** Wait until a message matching a predicate appears in the chat. */
async function waitForChatMessage(
  page: Page,
  predicate: (text: string) => boolean,
  timeout = 10000,
): Promise<string> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const msgs = await getChatMessages(page);
    const found = msgs.find(predicate);
    if (found) return found;
    await page.waitForTimeout(200);
  }
  throw new Error(`Chat message matching predicate not found within ${timeout}ms`);
}

// ============================================================
// TEST: Onboarding flow
// ============================================================
test.describe('Onboarding', () => {
  let context: BrowserContext;

  test.afterAll(async () => {
    if (context) await context.close().catch(() => {});
    await stopServer();
  });

  test.beforeAll(async () => {
    await startServer();
  });

  test('onboarding detects input and send button', async () => {
    context = await launchBrowser();
    const page = context.pages()[0] || (await context.newPage());
    await page.goto(`${serverUrl}?user=Test`);
    await page.waitForSelector('#chatInput');

    await doOnboarding(page, context);

    // Verify selectors were stored
    const sw = await getServiceWorker(context);
    const stored = await sw.evaluate((hostname: string) => {
      return new Promise<{ input: string | undefined; send: string | undefined }>((resolve) => {
        chrome.storage.local.get([
          `veil_input_selector_${hostname}`,
          `veil_send_selector_${hostname}`,
        ], (data) => {
          resolve({
            input: data[`veil_input_selector_${hostname}`],
            send: data[`veil_send_selector_${hostname}`],
          });
        });
      });
    }, '127.0.0.1');

    expect(stored.input).toBeTruthy();
    expect(stored.send).toBeTruthy();
    console.log('Input selector:', stored.input);
    console.log('Send selector:', stored.send);
    console.log('\n=== PASS: Onboarding ===');
  });
});

// ============================================================
// TEST: Full handshake + encrypted messaging
// ============================================================
test.describe('Veil Extension E2E', () => {
  let contextA: BrowserContext;
  let contextB: BrowserContext;

  test.afterAll(async () => {
    if (contextA) await contextA.close().catch(() => {});
    if (contextB) await contextB.close().catch(() => {});
    await stopServer();
  });

  test.beforeAll(async () => {
    await startServer();
  });

  test('two users complete auto-handshake and exchange encrypted messages', async () => {
    test.setTimeout(120000);

    contextA = await launchBrowser();
    contextB = await launchBrowser();

    const pageA = contextA.pages()[0] || (await contextA.newPage());
    const pageB = contextB.pages()[0] || (await contextB.newPage());

    await pageA.goto(`${serverUrl}?user=Alice`);
    await pageB.goto(`${serverUrl}?user=Bob`);

    await pageA.waitForSelector('#chatInput');
    await pageB.waitForSelector('#chatInput');

    // ===== ONBOARDING =====
    console.log('--- Onboarding both users ---');
    await doOnboarding(pageA, contextA);
    await doOnboarding(pageB, contextB);

    // ===== HANDSHAKE =====

    // Alice starts session — sends invite to chat
    console.log('--- Alice starts session ---');
    await sendToContent(contextA, { type: 'START_SESSION' });

    const aliceInvite = await waitForChatMessage(
      pageA, (m) => m.includes('[VL:I]'), 10000,
    );
    console.log('Alice sent invite (%d chars)', aliceInvite.length);

    // Get clean invite payload (without sender prefix)
    const aliceVeil = await getVeilPayloads(pageA);
    const invitePayload = aliceVeil.find((m) => m.includes('[VL:I]'))!;

    // Forward invite to Bob's chat, then Bob starts session
    // Bob's startSession will scan DOM, find the invite, and accept it
    await injectAndScan(pageB, contextB, invitePayload);
    console.log('--- Bob starts session ---');
    await sendToContent(contextB, { type: 'START_SESSION' });
    await pageB.waitForTimeout(2000);

    // Bob should have accepted and sent reply+verify
    const bobReply = await waitForChatMessage(
      pageB, (m) => m.includes('[VL:R]'), 10000,
    );
    console.log('Bob sent reply (%d chars)', bobReply.length);

    // Forward Bob's reply+verify to Alice
    const bobVeil = await getVeilPayloads(pageB);
    const replyPayload = bobVeil.find((m) => m.includes('[VL:R]'));
    expect(replyPayload).toBeTruthy();
    await injectAndScan(pageA, contextA, replyPayload!);
    // Give async completeHandshake time to finish
    await pageA.waitForTimeout(2000);

    // Verify both sides are established
    const stateA = await sendToContent(contextA, { type: 'GET_SESSION_STATE' }) as Record<string, unknown>;
    const stateB = await sendToContent(contextB, { type: 'GET_SESSION_STATE' }) as Record<string, unknown>;
    console.log('Alice: %s, Bob: %s', stateA?.handshakeState, stateB?.handshakeState);
    expect(stateA?.handshakeState).toBe('established');
    expect(stateB?.handshakeState).toBe('established');
    console.log('=== HANDSHAKE COMPLETE ===');

    // Verify Veil toggle is shown
    expect(await pageA.$('#veil-toggle-container')).toBeTruthy();
    expect(await pageB.$('#veil-toggle-container')).toBeTruthy();

    // ===== ENCRYPTED MESSAGING =====

    // Alice types and presses Enter — send interceptor encrypts
    // Note: the sender's own MutationObserver decrypts the message immediately
    // in the DOM, so we retrieve the encrypted payload via DEBUG_GET_LAST_ENCRYPTED
    console.log('--- Alice sends encrypted message ---');
    await pageA.fill('#chatInput', 'Hello Bob, this is encrypted!');
    await pageA.press('#chatInput', 'Enter');
    await pageA.waitForTimeout(1000);

    // Verify Alice sees her own message decrypted (self-decryption)
    await waitForChatMessage(
      pageA, (m) => m.includes('\u{1F512}') && m.includes('Hello Bob'), 5000,
    );

    // Get the encrypted payload that was sent
    const aliceEnc = await sendToContent(contextA, { type: 'DEBUG_GET_LAST_ENCRYPTED' }) as Record<string, unknown>;
    const encPayload = aliceEnc?.encrypted as string;
    expect(encPayload).toBeTruthy();
    console.log('Alice sent encrypted (%d chars)', encPayload.length);

    // Forward to Bob and scan
    await injectAndScan(pageB, contextB, encPayload);
    await pageB.waitForTimeout(1000);

    // Bob's content script should have decrypted inline
    const bobDecrypted = await waitForChatMessage(
      pageB, (m) => m.includes('\u{1F512}') && m.includes('Hello Bob'), 5000,
    );
    expect(bobDecrypted).toContain('Hello Bob, this is encrypted!');
    console.log('Bob decrypted:', bobDecrypted);

    // Bob sends a reply
    console.log('--- Bob sends encrypted reply ---');
    await pageB.fill('#chatInput', 'Hi Alice, encryption works!');
    await pageB.press('#chatInput', 'Enter');
    await pageB.waitForTimeout(1000);

    const bobEnc = await sendToContent(contextB, { type: 'DEBUG_GET_LAST_ENCRYPTED' }) as Record<string, unknown>;
    const bobEncPayload = bobEnc?.encrypted as string;
    expect(bobEncPayload).toBeTruthy();
    console.log('Bob sent encrypted (%d chars)', bobEncPayload.length);

    // Forward to Alice and scan
    await injectAndScan(pageA, contextA, bobEncPayload);
    await pageA.waitForTimeout(1000);

    const aliceDecrypted = await waitForChatMessage(
      pageA, (m) => m.includes('\u{1F512}') && m.includes('Hi Alice'), 5000,
    );
    expect(aliceDecrypted).toContain('Hi Alice, encryption works!');
    console.log('Alice decrypted:', aliceDecrypted);

    console.log('\n=== PASS: Full handshake + bidirectional encrypted messaging ===');
  });
});
