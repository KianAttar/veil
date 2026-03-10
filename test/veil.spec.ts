import { test, expect, chromium, BrowserContext, Page, Frame } from '@playwright/test';
import path from 'path';
import http from 'http';
import fs from 'fs';

const EXT_PATH = path.resolve(__dirname, '..');
const CHAT_PAGE = path.resolve(__dirname, 'chat-page.html');
const SIDEBAR_WIDTH = 360;

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

async function waitForSidebarFrame(page: Page, timeout = 10000): Promise<Frame> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const frame = page.frames().find((f) => f.url().includes('sidebar.html'));
    if (frame) return frame;
    await page.waitForTimeout(200);
  }
  throw new Error('Sidebar frame not found');
}

async function openSidebar(page: Page, context: BrowserContext): Promise<void> {
  let sw = context.serviceWorkers().find((w) => w.url().includes('background.js'));
  if (!sw) {
    sw = await context.waitForEvent('serviceworker', {
      predicate: (w) => w.url().includes('background.js'),
      timeout: 10000,
    });
  }
  await sw.evaluate(() => {
    return new Promise<void>((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].id !== undefined) {
          chrome.tabs.sendMessage(tabs[0].id, { type: 'TOGGLE_SIDEBAR' }, () => resolve());
        } else resolve();
      });
    });
  });
}

async function closeSidebar(page: Page, context: BrowserContext): Promise<void> {
  await openSidebar(page, context);
}

async function getReplyCode(sidebar: Frame): Promise<string | null> {
  const systemMsgs = await sidebar.$$eval('.msg-system', (els) =>
    els.map((e) => e.textContent ?? ''),
  );
  for (const m of systemMsgs) {
    if (m.includes('\u200C\u200B')) return m;
  }
  return null;
}

async function getEncryptedFromChat(page: Page): Promise<string | null> {
  const msgs = await page.$$eval('#messages .message', (els) =>
    els.map((el) => el.textContent ?? ''),
  );
  for (const m of [...msgs].reverse()) {
    if (m.includes('\u200B\u200C\u200D')) return m.replace(/^[^:]+:\s*/, '');
  }
  return null;
}

async function injectMessageToChat(page: Page, text: string): Promise<void> {
  await page.evaluate((t) => {
    const div = document.createElement('div');
    div.className = 'message';
    div.appendChild(document.createTextNode(t));
    document.getElementById('messages')!.appendChild(div);
  }, text);
}

// ============================================================
// TEST: Sidebar pushes page content (no overlap)
// ============================================================
test.describe('Sidebar layout - no overlap', () => {
  let context: BrowserContext;

  test.afterAll(async () => {
    if (context) await context.close().catch(() => {});
    await stopServer();
  });

  test.beforeAll(async () => {
    await startServer();
  });

  test('fixed-position page content is pushed left when sidebar opens', async () => {
    context = await launchBrowser();
    const page = context.pages()[0] || (await context.newPage());
    await page.goto(`${serverUrl}?user=Test`);
    await page.waitForSelector('#app-shell');

    const beforeRect = await page.evaluate(() => {
      const el = document.getElementById('app-shell')!;
      const rect = el.getBoundingClientRect();
      return { left: rect.left, right: rect.right, width: rect.width };
    });
    const viewportWidth = await page.evaluate(() => window.innerWidth);
    expect(beforeRect.right).toBeGreaterThanOrEqual(viewportWidth - 2);
    console.log(
      'Before sidebar: app-shell right edge = %d, viewport = %d',
      beforeRect.right,
      viewportWidth,
    );

    await openSidebar(page, context);
    await waitForSidebarFrame(page);
    await page.waitForTimeout(500);

    const bodyRect = await page.evaluate(() => {
      const rect = document.body.getBoundingClientRect();
      return { left: rect.left, right: rect.right, width: rect.width };
    });
    const sidebarLeft = viewportWidth - SIDEBAR_WIDTH;
    console.log('After sidebar: body width = %d, expected ~%d', bodyRect.width, sidebarLeft);

    expect(bodyRect.width).toBeLessThanOrEqual(sidebarLeft + 5);

    const afterRect = await page.evaluate(() => {
      const el = document.getElementById('app-shell')!;
      const rect = el.getBoundingClientRect();
      return { left: rect.left, right: rect.right, width: rect.width };
    });
    console.log(
      'After sidebar: app-shell right = %d, sidebar starts at = %d',
      afterRect.right,
      sidebarLeft,
    );
    expect(afterRect.right).toBeLessThanOrEqual(sidebarLeft + 5);
    expect(afterRect.width).toBeLessThan(beforeRect.width);

    const inputRect = await page.evaluate(() => {
      return document.getElementById('inputArea')!.getBoundingClientRect();
    });
    expect(inputRect.right).toBeLessThanOrEqual(sidebarLeft + 5);
    console.log('Input area right edge = %d (must be <= %d)', inputRect.right, sidebarLeft);

    const headerRect = await page.evaluate(() => {
      return document.getElementById('app-header')!.getBoundingClientRect();
    });
    expect(headerRect.right).toBeLessThanOrEqual(sidebarLeft + 5);

    const sidebarRect = await page.evaluate(() => {
      const el = document.getElementById('veil-sidebar-container');
      return el ? el.getBoundingClientRect() : null;
    });
    expect(sidebarRect).toBeTruthy();
    expect(sidebarRect!.left).toBeGreaterThanOrEqual(sidebarLeft - 5);
    console.log('Sidebar left edge = %d', sidebarRect!.left);

    await closeSidebar(page, context);
    await page.waitForTimeout(500);

    const restoredRect = await page.evaluate(() => {
      const el = document.getElementById('app-shell')!;
      const rect = el.getBoundingClientRect();
      return { left: rect.left, right: rect.right, width: rect.width };
    });
    expect(restoredRect.right).toBeGreaterThanOrEqual(viewportWidth - 2);
    console.log('After close: app-shell right edge restored to %d', restoredRect.right);

    console.log('\n=== PASS: Sidebar pushes fixed-position content, no overlap ===');
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

  test('two users complete handshake and exchange encrypted messages', async () => {
    test.setTimeout(90000);

    contextA = await launchBrowser();
    contextB = await launchBrowser();

    const pageA = contextA.pages()[0] || (await contextA.newPage());
    const pageB = contextB.pages()[0] || (await contextB.newPage());

    await pageA.goto(`${serverUrl}?user=Alice`);
    await pageB.goto(`${serverUrl}?user=Bob`);

    await pageA.waitForSelector('#chatInput');
    await pageB.waitForSelector('#chatInput');

    await openSidebar(pageA, contextA);
    await openSidebar(pageB, contextB);

    const sidebarA = await waitForSidebarFrame(pageA);
    const sidebarB = await waitForSidebarFrame(pageB);

    // Select language
    await sidebarA.click('.lang-btn[data-lang="en"]');
    await sidebarB.click('.lang-btn[data-lang="en"]');
    await sidebarA.waitForSelector('#panelNoSession.active');
    await sidebarB.waitForSelector('#panelNoSession.active');

    // ===== HANDSHAKE =====

    await sidebarA.click('#btnStartSession');
    await sidebarA.waitForSelector('#panelHandshake.active', { timeout: 5000 });
    await pageA.waitForTimeout(500);

    const inviteCode = await sidebarA.textContent('#inviteCode');
    expect(inviteCode!.length).toBeGreaterThan(10);
    console.log('Alice created invite (%d chars)', inviteCode!.length);

    await sidebarB.click('#btnCompleteHandshake');
    await sidebarB.waitForSelector('#panelHandshakeReceived.active');
    await sidebarB.fill('#pasteInviteInput', inviteCode!);
    await sidebarB.click('#btnAcceptHandshake');

    await sidebarB.waitForSelector('#panelSession.active', { timeout: 10000 });
    console.log('Bob connected');

    await pageB.waitForTimeout(1000);
    const replyCode = await getReplyCode(sidebarB);
    expect(replyCode).toBeTruthy();
    console.log('Reply code (%d chars)', replyCode!.length);

    await injectMessageToChat(pageA, replyCode!);
    await pageA.waitForTimeout(4000);

    await sidebarA.waitForSelector('#panelSession.active', { timeout: 10000 });
    console.log('Alice connected - HANDSHAKE COMPLETE');

    // ===== MESSAGING =====

    await sidebarA.fill('#composeInput', 'Hello Bob, this is encrypted!');
    await sidebarA.click('#btnSend');
    await pageA.waitForTimeout(500);

    let aliceEnc: string | null = null;
    if (await sidebarA.$('#panelCopyFallback.active')) {
      aliceEnc = await sidebarA.textContent('#fallbackText');
      await sidebarA.click('#btnBackFromFallback');
    } else {
      aliceEnc = await getEncryptedFromChat(pageA);
    }

    await sidebarA.waitForSelector('.msg-you');
    expect(await sidebarA.textContent('.msg-you')).toBe('Hello Bob, this is encrypted!');

    if (aliceEnc) {
      await injectMessageToChat(pageB, aliceEnc);
      await pageB.waitForTimeout(3000);
      expect(await sidebarB.textContent('.msg-them')).toBe('Hello Bob, this is encrypted!');
      console.log("Bob decrypted Alice's message");
    }

    await sidebarB.fill('#composeInput', 'Hi Alice, encryption works!');
    await sidebarB.click('#btnSend');
    await pageB.waitForTimeout(500);

    let bobEnc: string | null = null;
    if (await sidebarB.$('#panelCopyFallback.active')) {
      bobEnc = await sidebarB.textContent('#fallbackText');
      await sidebarB.click('#btnBackFromFallback');
    } else {
      bobEnc = await getEncryptedFromChat(pageB);
    }

    await sidebarB.waitForSelector('.msg-you');

    if (bobEnc) {
      await injectMessageToChat(pageA, bobEnc);
      await pageA.waitForTimeout(3000);
      expect(await sidebarA.textContent('.msg-them')).toBe('Hi Alice, encryption works!');
      console.log("Alice decrypted Bob's message");
    }

    console.log('\n=== PASS: Handshake + bidirectional encrypted messaging ===');
  });
});
