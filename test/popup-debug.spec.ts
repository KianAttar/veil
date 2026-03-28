import { test, chromium, BrowserContext, Page } from '@playwright/test';
import path from 'path';
import http from 'http';
import fs from 'fs';

const EXT_PATH = path.resolve(__dirname, '..');
const DEMO_PAGE = path.resolve(__dirname, '../demo/index.html');

let server: http.Server;
let serverUrl: string;

function startServer(): Promise<void> {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      fs.createReadStream(DEMO_PAGE).pipe(res);
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

/** Send message to content script of the ACTIVE tab. Must bringToFront first. */
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

async function doOnboarding(page: Page, context: BrowserContext): Promise<void> {
  await page.bringToFront();
  await sendToContent(context, { type: 'START_ONBOARDING' });
  await page.waitForTimeout(300);
  await page.fill('#chatInput', 'test');
  await page.waitForTimeout(500);
  await page.click('#sendBtn');
  await page.waitForTimeout(500);
}

test('debug: trace GET_SESSION_STATE through handshake', async () => {
  await startServer();
  const ctx = await launchBrowser();

  try {
    const alice = await ctx.newPage();
    await alice.goto(`${serverUrl}/?name=Alice`);
    await alice.waitForTimeout(1000);

    const bob = await ctx.newPage();
    await bob.goto(`${serverUrl}/?name=Bob`);
    await bob.waitForTimeout(1000);

    // Onboarding
    await doOnboarding(alice, ctx);
    await doOnboarding(bob, ctx);

    // Pre-session state
    await alice.bringToFront();
    const pre = await sendToContent(ctx, { type: 'GET_SESSION_STATE' });
    console.log('=== PRE-SESSION (Alice) ===');
    console.log(JSON.stringify(pre, null, 2));

    // Start session on Alice
    await sendToContent(ctx, { type: 'START_SESSION' });
    await alice.waitForTimeout(2000);

    const afterInvite = await sendToContent(ctx, { type: 'GET_SESSION_STATE' });
    console.log('=== AFTER INVITE (Alice) ===');
    console.log(JSON.stringify(afterInvite, null, 2));

    // Bob starts session
    await bob.bringToFront();
    await bob.waitForTimeout(500);
    await sendToContent(ctx, { type: 'START_SESSION' });
    await bob.waitForTimeout(3000);

    const bobAfter = await sendToContent(ctx, { type: 'GET_SESSION_STATE' });
    console.log('=== BOB AFTER START_SESSION ===');
    console.log(JSON.stringify(bobAfter, null, 2));

    // Force scan on Alice to pick up Bob's reply
    await alice.bringToFront();
    await alice.waitForTimeout(500);
    await sendToContent(ctx, { type: 'DEBUG_SCAN' });
    await alice.waitForTimeout(3000);

    const aliceFinal = await sendToContent(ctx, { type: 'GET_SESSION_STATE' });
    console.log('=== ALICE FINAL ===');
    console.log(JSON.stringify(aliceFinal, null, 2));

    await bob.bringToFront();
    await bob.waitForTimeout(500);
    const bobFinal = await sendToContent(ctx, { type: 'GET_SESSION_STATE' });
    console.log('=== BOB FINAL ===');
    console.log(JSON.stringify(bobFinal, null, 2));

    // Log console messages from both pages
    const aliceLogs: string[] = [];
    const bobLogs: string[] = [];
    alice.on('console', (m) => aliceLogs.push(m.text()));
    bob.on('console', (m) => bobLogs.push(m.text()));

    // Gather Veil-related console messages from page
    await alice.bringToFront();
    const aliceConsoleDump = await alice.evaluate(() => {
      // Can't get past console logs, but let's check current state
      return {
        storageAvailable: typeof chrome !== 'undefined' && !!chrome?.storage?.session,
        bodyTextLength: document.body.textContent?.length,
        veilTags: document.body.textContent?.match(/\[VL:[A-Z]\]/g),
      };
    });
    console.log('=== ALICE PAGE STATE ===');
    console.log(JSON.stringify(aliceConsoleDump, null, 2));

  } finally {
    await ctx.close();
    await stopServer();
  }
});
