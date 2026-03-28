/**
 * Veil Extension — Exploration / Bug-hunting test
 *
 * Launches TWO separate browser contexts (separate Chrome instances),
 * performs the full flow (onboarding, handshake, encrypted messaging),
 * and collects every console message, error, warning, and DOM anomaly.
 *
 * This does NOT assert correctness — it gathers information.
 */
import { test, chromium, BrowserContext, Page, ConsoleMessage, Worker } from '@playwright/test';
import path from 'path';
import http from 'http';
import fs from 'fs';

const EXT_PATH = path.resolve(__dirname, '..');
const CHAT_PAGE = path.resolve(__dirname, 'chat-page.html');

// ============================================================
// Logging infrastructure
// ============================================================

interface LogEntry {
  time: number;
  source: string;
  level: string;
  text: string;
}

const allLogs: LogEntry[] = [];

function log(source: string, level: string, text: string): void {
  const entry: LogEntry = { time: Date.now(), source, level, text };
  allLogs.push(entry);
  const tag = `[${source}] [${level.toUpperCase()}]`;
  if (level === 'error') {
    console.error(tag, text);
  } else if (level === 'warning') {
    console.warn(tag, text);
  } else {
    console.log(tag, text);
  }
}

// ============================================================
// HTTP server for chat page
// ============================================================

let server: http.Server;
let serverUrl: string;

function startServer(): Promise<void> {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      // Serve demo page or test chat page depending on path
      const url = new URL(req.url!, `http://127.0.0.1`);
      let filePath = CHAT_PAGE;
      if (url.pathname === '/demo') {
        filePath = path.resolve(__dirname, '..', 'demo', 'index.html');
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      fs.createReadStream(filePath).pipe(res);
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      serverUrl = `http://127.0.0.1:${addr.port}`;
      log('server', 'info', `Started on ${serverUrl}`);
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

// ============================================================
// Browser launch helpers
// ============================================================

function launchBrowser(label: string): Promise<BrowserContext> {
  log(label, 'info', 'Launching browser context');
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

async function getServiceWorker(context: BrowserContext, label: string): Promise<Worker> {
  let sw = context.serviceWorkers().find((w) => w.url().includes('background.js'));
  if (!sw) {
    log(label, 'info', 'Waiting for service worker...');
    sw = await context.waitForEvent('serviceworker', {
      predicate: (w) => w.url().includes('background.js'),
      timeout: 15000,
    });
  }
  log(label, 'info', `Service worker found: ${sw.url()}`);
  return sw;
}

async function sendToContent(context: BrowserContext, label: string, msg: Record<string, unknown>): Promise<unknown> {
  const sw = await getServiceWorker(context, label);
  log(label, 'info', `sendToContent: ${JSON.stringify(msg)}`);
  const result = await sw.evaluate((m) => {
    return new Promise<unknown>((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].id !== undefined) {
          chrome.tabs.sendMessage(tabs[0].id, m, (resp) => {
            if (chrome.runtime.lastError) {
              resolve({ __error: chrome.runtime.lastError.message });
            } else {
              resolve(resp);
            }
          });
        } else {
          resolve({ __error: 'no active tab' });
        }
      });
    });
  }, msg);
  log(label, 'info', `sendToContent result: ${JSON.stringify(result)}`);
  return result;
}

// ============================================================
// Console message collector — attaches to a Page
// ============================================================

function attachConsoleCollector(page: Page, label: string): void {
  page.on('console', (msg: ConsoleMessage) => {
    const level = msg.type(); // 'log', 'error', 'warning', 'info', etc.
    const text = msg.text();
    log(label, level, text);
  });

  page.on('pageerror', (error) => {
    log(label, 'error', `PAGE_ERROR: ${error.message}`);
  });
}

// ============================================================
// Onboarding helper
// ============================================================

async function doOnboarding(page: Page, context: BrowserContext, label: string): Promise<void> {
  log(label, 'info', '--- Starting onboarding ---');
  await sendToContent(context, label, { type: 'START_ONBOARDING' });
  await page.waitForTimeout(500);

  // Type in input to trigger input detection
  await page.fill('#chatInput', 'onboarding test');
  await page.waitForTimeout(500);

  // Click send button to trigger send detection
  await page.click('#sendBtn');
  await page.waitForTimeout(500);

  // Verify selectors were stored
  const sw = await getServiceWorker(context, label);
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

  log(label, 'info', `Onboarding result — input: "${stored.input}", send: "${stored.send}"`);
  if (!stored.input) log(label, 'error', 'ONBOARDING FAILED: no input selector stored');
  if (!stored.send) log(label, 'error', 'ONBOARDING FAILED: no send selector stored');
}

// ============================================================
// DOM injection + scan helpers
// ============================================================

async function injectAndScan(page: Page, context: BrowserContext, label: string, text: string): Promise<unknown> {
  log(label, 'info', `Injecting Veil payload (${text.length} chars) into DOM`);
  await page.evaluate((t) => {
    const div = document.createElement('div');
    div.className = 'message';
    div.appendChild(document.createTextNode(t));
    document.getElementById('messages')!.appendChild(div);
  }, text);
  await page.waitForTimeout(300);
  const result = await sendToContent(context, label, { type: 'DEBUG_SCAN' });
  await page.waitForTimeout(500);
  return result;
}

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

async function getChatMessages(page: Page): Promise<string[]> {
  return page.$$eval('#messages .message', (els) =>
    els.map((el) => el.textContent ?? ''),
  );
}

async function waitForChatMessage(
  page: Page,
  predicate: (text: string) => boolean,
  timeout = 15000,
): Promise<string | null> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const msgs = await getChatMessages(page);
    const found = msgs.find(predicate);
    if (found) return found;
    await page.waitForTimeout(200);
  }
  return null; // Don't throw — we want to report, not crash
}

// ============================================================
// DOM inspection helpers
// ============================================================

interface DomReport {
  hasVeilToggle: boolean;
  toggleText: string | null;
  hasToast: boolean;
  toastText: string | null;
  messageCount: number;
  veilMessageCount: number;
  decryptedCount: number;
  rawCiphertextCount: number;
  unexpectedElements: string[];
}

async function inspectDom(page: Page, label: string): Promise<DomReport> {
  const report = await page.evaluate(() => {
    const toggle = document.getElementById('veil-toggle-container');
    const toast = document.getElementById('veil-toast');
    const messages = document.querySelectorAll('#messages .message');

    let veilMessageCount = 0;
    let decryptedCount = 0;
    let rawCiphertextCount = 0;

    messages.forEach((m) => {
      const text = m.textContent || '';
      if (text.includes('[VL:')) veilMessageCount++;
      if (text.includes('\u{1F512}')) decryptedCount++;
      // Check for raw base64 ciphertext that wasn't decrypted
      if (text.includes('[VL:E]') && !text.includes('\u{1F512}')) rawCiphertextCount++;
    });

    // Check for unexpected Veil-injected elements
    const unexpectedElements: string[] = [];
    const allVeilEls = document.querySelectorAll('[id^="veil-"]');
    allVeilEls.forEach((el) => {
      const id = el.id;
      if (id !== 'veil-toggle-container' && id !== 'veil-toast'
          && id !== 'veil-toggle-icon' && id !== 'veil-toggle-label') {
        unexpectedElements.push(id);
      }
    });

    return {
      hasVeilToggle: !!toggle,
      toggleText: toggle?.textContent?.trim() ?? null,
      hasToast: !!toast,
      toastText: toast?.textContent?.trim() ?? null,
      messageCount: messages.length,
      veilMessageCount,
      decryptedCount,
      rawCiphertextCount,
      unexpectedElements,
    };
  });

  log(label, 'info', `DOM Report: ${JSON.stringify(report, null, 2)}`);
  return report;
}

// ============================================================
// Popup state inspection
// ============================================================

async function inspectPopupState(context: BrowserContext, label: string): Promise<Record<string, unknown> | null> {
  // Read session storage directly via service worker
  const sw = await getServiceWorker(context, label);
  const state = await sw.evaluate(() => {
    return new Promise<Record<string, unknown>>((resolve) => {
      chrome.storage.session.get(null, (data) => {
        resolve(data as Record<string, unknown>);
      });
    });
  });
  log(label, 'info', `Storage.session state: ${JSON.stringify(state, null, 2)}`);

  // Also check local storage
  const local = await sw.evaluate(() => {
    return new Promise<Record<string, unknown>>((resolve) => {
      chrome.storage.local.get(null, (data) => {
        resolve(data as Record<string, unknown>);
      });
    });
  });
  log(label, 'info', `Storage.local state: ${JSON.stringify(local, null, 2)}`);

  return state;
}

// ============================================================
// MutationObserver firing count
// ============================================================

async function getMutationCount(page: Page, label: string): Promise<number> {
  // Count how many "MutationObserver fired" lines we logged
  const count = allLogs.filter(
    (e) => e.source === label && e.text.includes('MutationObserver fired'),
  ).length;
  log(label, 'info', `MutationObserver fire count: ${count}`);
  return count;
}

// ============================================================
// MAIN EXPLORATION TEST
// ============================================================

test('Veil full-flow exploration — two browser contexts', async () => {
  test.setTimeout(180000); // 3 minutes

  await startServer();

  let contextA: BrowserContext | null = null;
  let contextB: BrowserContext | null = null;

  try {
    // ===== LAUNCH BROWSERS =====
    contextA = await launchBrowser('Alice');
    contextB = await launchBrowser('Bob');

    const pageA = contextA.pages()[0] || (await contextA.newPage());
    const pageB = contextB.pages()[0] || (await contextB.newPage());

    // Attach console collectors BEFORE navigation
    attachConsoleCollector(pageA, 'Alice-page');
    attachConsoleCollector(pageB, 'Bob-page');

    // ===== NAVIGATE =====
    log('Alice', 'info', 'Navigating to chat page');
    await pageA.goto(`${serverUrl}?user=Alice`);
    await pageA.waitForSelector('#chatInput');

    log('Bob', 'info', 'Navigating to chat page');
    await pageB.goto(`${serverUrl}?user=Bob`);
    await pageB.waitForSelector('#chatInput');

    // Give content scripts time to initialize
    await pageA.waitForTimeout(1000);
    await pageB.waitForTimeout(1000);

    // ===== INITIAL STATE =====
    log('test', 'info', '========== INITIAL STATE ==========');
    const initialStateA = await sendToContent(contextA, 'Alice', { type: 'GET_SESSION_STATE' });
    const initialStateB = await sendToContent(contextB, 'Bob', { type: 'GET_SESSION_STATE' });
    log('test', 'info', `Alice initial: ${JSON.stringify(initialStateA)}`);
    log('test', 'info', `Bob initial: ${JSON.stringify(initialStateB)}`);

    // ===== ONBOARDING =====
    log('test', 'info', '========== ONBOARDING ==========');
    await doOnboarding(pageA, contextA, 'Alice');
    await doOnboarding(pageB, contextB, 'Bob');

    // Check popup-visible state after onboarding
    await inspectPopupState(contextA, 'Alice');
    await inspectPopupState(contextB, 'Bob');

    // ===== START SESSION ON ALICE (sends invite) =====
    log('test', 'info', '========== ALICE STARTS SESSION ==========');
    await sendToContent(contextA, 'Alice', { type: 'START_SESSION' });
    await pageA.waitForTimeout(2000);

    // Check if invite appeared in Alice's chat
    const aliceInvite = await waitForChatMessage(pageA, (m) => m.includes('[VL:I]'), 15000);
    if (aliceInvite) {
      log('test', 'info', `Alice invite found (${aliceInvite.length} chars)`);
    } else {
      log('test', 'error', 'ALICE INVITE NOT FOUND in chat DOM within 15s');
    }

    // Get clean payload
    const aliceVeil = await getVeilPayloads(pageA);
    log('test', 'info', `Alice Veil payloads: ${aliceVeil.length} items`);
    aliceVeil.forEach((p, i) => log('test', 'info', `  Payload[${i}]: ${p.substring(0, 80)}...`));
    const invitePayload = aliceVeil.find((m) => m.includes('[VL:I]'));

    if (!invitePayload) {
      log('test', 'error', 'FATAL: No [VL:I] payload found — cannot continue handshake');
      return;
    }

    // Check Alice state after sending invite
    const aliceAfterInvite = await sendToContent(contextA, 'Alice', { type: 'GET_SESSION_STATE' });
    log('test', 'info', `Alice after invite: ${JSON.stringify(aliceAfterInvite)}`);

    // Also get Alice's DEBUG_SCAN result (includes nonce)
    const aliceScan = await sendToContent(contextA, 'Alice', { type: 'DEBUG_SCAN' });
    log('test', 'info', `Alice DEBUG_SCAN: ${JSON.stringify(aliceScan)}`);

    // ===== FORWARD INVITE TO BOB =====
    log('test', 'info', '========== FORWARD INVITE TO BOB ==========');
    await injectAndScan(pageB, contextB, 'Bob', invitePayload);

    // ===== BOB STARTS SESSION (should find and accept invite) =====
    log('test', 'info', '========== BOB STARTS SESSION ==========');
    await sendToContent(contextB, 'Bob', { type: 'START_SESSION' });
    await pageB.waitForTimeout(3000);

    // Check Bob's state
    const bobAfterStart = await sendToContent(contextB, 'Bob', { type: 'GET_SESSION_STATE' });
    log('test', 'info', `Bob after start: ${JSON.stringify(bobAfterStart)}`);

    // Check if Bob sent reply+verify
    const bobReply = await waitForChatMessage(pageB, (m) => m.includes('[VL:R]'), 15000);
    if (bobReply) {
      log('test', 'info', `Bob reply found (${bobReply.length} chars)`);
    } else {
      log('test', 'error', 'BOB REPLY NOT FOUND in chat DOM within 15s');
    }

    const bobVeil = await getVeilPayloads(pageB);
    log('test', 'info', `Bob Veil payloads: ${bobVeil.length} items`);
    bobVeil.forEach((p, i) => log('test', 'info', `  Payload[${i}]: ${p.substring(0, 80)}...`));
    const replyPayload = bobVeil.find((m) => m.includes('[VL:R]'));

    if (!replyPayload) {
      log('test', 'error', 'FATAL: No [VL:R] payload found — cannot complete handshake');
      // Try to gather as much info as possible before stopping
      const bobAllMsgs = await getChatMessages(pageB);
      log('test', 'info', `Bob all messages: ${JSON.stringify(bobAllMsgs)}`);
      await inspectDom(pageB, 'Bob');
      await inspectPopupState(contextB, 'Bob');
      return;
    }

    // Check if Bob also sent a [VL:V] (verify) tag
    const hasVerify = replyPayload.includes('[VL:V]') || bobVeil.some((p) => p.includes('[VL:V]'));
    log('test', 'info', `Bob verify tag present: ${hasVerify}`);

    // ===== FORWARD BOB'S REPLY+VERIFY TO ALICE =====
    log('test', 'info', '========== FORWARD REPLY+VERIFY TO ALICE ==========');
    await injectAndScan(pageA, contextA, 'Alice', replyPayload);

    // If verify was separate, forward it too
    const verifyPayload = bobVeil.find((m) => m.includes('[VL:V]') && !m.includes('[VL:R]'));
    if (verifyPayload) {
      log('test', 'info', 'Forwarding separate verify payload to Alice');
      await injectAndScan(pageA, contextA, 'Alice', verifyPayload);
    }

    // Give Alice time to process
    await pageA.waitForTimeout(2000);

    // ===== TRIGGER DEBUG_SCAN ON ALICE =====
    log('test', 'info', '========== DEBUG_SCAN ALICE ==========');
    const aliceDebugScan = await sendToContent(contextA, 'Alice', { type: 'DEBUG_SCAN' });
    log('test', 'info', `Alice DEBUG_SCAN result: ${JSON.stringify(aliceDebugScan)}`);
    await pageA.waitForTimeout(1000);

    // ===== CHECK BOTH SIDES ESTABLISHED =====
    log('test', 'info', '========== CHECK ESTABLISHED ==========');
    const stateA = await sendToContent(contextA, 'Alice', { type: 'GET_SESSION_STATE' }) as Record<string, unknown> | null;
    const stateB = await sendToContent(contextB, 'Bob', { type: 'GET_SESSION_STATE' }) as Record<string, unknown> | null;
    log('test', 'info', `Alice state: ${JSON.stringify(stateA)}`);
    log('test', 'info', `Bob state: ${JSON.stringify(stateB)}`);

    const aliceEstablished = stateA?.handshakeState === 'established';
    const bobEstablished = stateB?.handshakeState === 'established';
    log('test', aliceEstablished ? 'info' : 'error', `Alice established: ${aliceEstablished}`);
    log('test', bobEstablished ? 'info' : 'error', `Bob established: ${bobEstablished}`);

    // Check fingerprints match
    if (stateA?.fingerprint && stateB?.fingerprint) {
      const fingerprintMatch = stateA.fingerprint === stateB.fingerprint;
      log('test', fingerprintMatch ? 'info' : 'error',
        `Fingerprint match: ${fingerprintMatch} (Alice: ${stateA.fingerprint}, Bob: ${stateB.fingerprint})`);
    } else {
      log('test', 'warning', `Fingerprints missing — Alice: ${stateA?.fingerprint}, Bob: ${stateB?.fingerprint}`);
    }

    // ===== INSPECT VEIL TOGGLE =====
    log('test', 'info', '========== VEIL TOGGLE CHECK ==========');
    const domA = await inspectDom(pageA, 'Alice');
    const domB = await inspectDom(pageB, 'Bob');
    if (!domA.hasVeilToggle && aliceEstablished) {
      log('test', 'error', 'Alice: MISSING Veil toggle despite established session');
    }
    if (!domB.hasVeilToggle && bobEstablished) {
      log('test', 'error', 'Bob: MISSING Veil toggle despite established session');
    }

    // ===== ENCRYPTED MESSAGING: ALICE -> BOB =====
    log('test', 'info', '========== ENCRYPTED MESSAGE: ALICE -> BOB ==========');
    if (aliceEstablished) {
      await pageA.fill('#chatInput', 'Hello Bob, this is a secret message!');
      await pageA.press('#chatInput', 'Enter');
      await pageA.waitForTimeout(2000);

      const aliceMsgsAfterSend = await getChatMessages(pageA);
      log('test', 'info', `Alice messages after send: ${JSON.stringify(aliceMsgsAfterSend)}`);

      const aliceEncPayloads = await getVeilPayloads(pageA);
      const encPayload = aliceEncPayloads.find((m) => m.includes('[VL:E]'));
      if (encPayload) {
        log('test', 'info', `Alice encrypted payload found (${encPayload.length} chars)`);

        // Forward to Bob
        await injectAndScan(pageB, contextB, 'Bob', encPayload);
        await pageB.waitForTimeout(2000);

        // Check if Bob decrypted it
        const bobDecrypted = await waitForChatMessage(
          pageB, (m) => m.includes('\u{1F512}'), 10000,
        );
        if (bobDecrypted) {
          const containsOriginal = bobDecrypted.includes('Hello Bob, this is a secret message!');
          log('test', containsOriginal ? 'info' : 'error',
            `Bob decrypted: "${bobDecrypted}" — contains original: ${containsOriginal}`);
        } else {
          log('test', 'error', 'Bob FAILED TO DECRYPT Alice message');
          // Check what the message looks like
          const bobMsgs = await getChatMessages(pageB);
          log('test', 'info', `Bob messages: ${JSON.stringify(bobMsgs)}`);
        }
      } else {
        log('test', 'error', 'Alice FAILED TO ENCRYPT message (no [VL:E] payload found)');
        // Check if message was sent as plaintext
        const sent = aliceMsgsAfterSend.find((m) => m.includes('Hello Bob'));
        if (sent) {
          log('test', 'warning', `Message appears to have been sent as plaintext: "${sent}"`);
        }
      }
    } else {
      log('test', 'warning', 'Skipping Alice->Bob encrypted msg — session not established');
    }

    // ===== ENCRYPTED MESSAGING: BOB -> ALICE =====
    log('test', 'info', '========== ENCRYPTED MESSAGE: BOB -> ALICE ==========');
    if (bobEstablished) {
      await pageB.fill('#chatInput', 'Hi Alice, encryption works!');
      await pageB.press('#chatInput', 'Enter');
      await pageB.waitForTimeout(2000);

      const bobMsgsAfterSend = await getChatMessages(pageB);
      log('test', 'info', `Bob messages after send: ${JSON.stringify(bobMsgsAfterSend)}`);

      const bobEncPayloads = await getVeilPayloads(pageB);
      const bobEncPayload = bobEncPayloads.find((m) => m.includes('[VL:E]'));
      if (bobEncPayload) {
        log('test', 'info', `Bob encrypted payload found (${bobEncPayload.length} chars)`);

        // Forward to Alice
        await injectAndScan(pageA, contextA, 'Alice', bobEncPayload);
        await pageA.waitForTimeout(2000);

        // Check if Alice decrypted it
        const aliceDecrypted = await waitForChatMessage(
          pageA, (m) => m.includes('\u{1F512}') && m.includes('Hi Alice'), 10000,
        );
        if (aliceDecrypted) {
          log('test', 'info', `Alice decrypted: "${aliceDecrypted}"`);
        } else {
          log('test', 'error', 'Alice FAILED TO DECRYPT Bob message');
          const aliceMsgs = await getChatMessages(pageA);
          log('test', 'info', `Alice messages: ${JSON.stringify(aliceMsgs)}`);
        }
      } else {
        log('test', 'error', 'Bob FAILED TO ENCRYPT message (no [VL:E] payload found)');
      }
    } else {
      log('test', 'warning', 'Skipping Bob->Alice encrypted msg — session not established');
    }

    // ===== POPUP STATE =====
    log('test', 'info', '========== POPUP STATE ==========');
    await inspectPopupState(contextA, 'Alice');
    await inspectPopupState(contextB, 'Bob');

    // ===== MUTATION OBSERVER FIRE COUNT =====
    log('test', 'info', '========== MUTATION OBSERVER ==========');
    await getMutationCount(pageA, 'Alice-page');
    await getMutationCount(pageB, 'Bob-page');

    // ===== FINAL DOM INSPECTION =====
    log('test', 'info', '========== FINAL DOM INSPECTION ==========');
    const finalDomA = await inspectDom(pageA, 'Alice');
    const finalDomB = await inspectDom(pageB, 'Bob');

    // ===== SUMMARY REPORT =====
    log('test', 'info', '');
    log('test', 'info', '=================================================================');
    log('test', 'info', '                    EXPLORATION SUMMARY');
    log('test', 'info', '=================================================================');

    // Count issues by severity
    const errors = allLogs.filter((e) => e.level === 'error');
    const warnings = allLogs.filter((e) => e.level === 'warning');
    const pageErrors = allLogs.filter((e) => e.text.startsWith('PAGE_ERROR:'));
    const storageFailures = allLogs.filter((e) => e.text.includes('storage') && e.level === 'error');
    const fingerprintIssues = allLogs.filter((e) => e.text.includes('fingerprint') && (e.level === 'error' || e.level === 'warning'));
    const mutationFires = allLogs.filter((e) => e.text.includes('MutationObserver fired'));

    log('test', 'info', `Total console entries: ${allLogs.length}`);
    log('test', 'info', `  Errors: ${errors.length}`);
    log('test', 'info', `  Warnings: ${warnings.length}`);
    log('test', 'info', `  Page errors (crashes): ${pageErrors.length}`);
    log('test', 'info', `  Storage failures: ${storageFailures.length}`);
    log('test', 'info', `  Fingerprint issues: ${fingerprintIssues.length}`);
    log('test', 'info', `  MutationObserver fires: ${mutationFires.length}`);
    log('test', 'info', '');
    log('test', 'info', `Alice established: ${aliceEstablished}`);
    log('test', 'info', `Bob established: ${bobEstablished}`);
    log('test', 'info', `Alice toggle: ${finalDomA.hasVeilToggle} (${finalDomA.toggleText})`);
    log('test', 'info', `Bob toggle: ${finalDomB.hasVeilToggle} (${finalDomB.toggleText})`);
    log('test', 'info', `Alice decrypted msgs: ${finalDomA.decryptedCount}`);
    log('test', 'info', `Bob decrypted msgs: ${finalDomB.decryptedCount}`);
    log('test', 'info', `Alice raw ciphertext remaining: ${finalDomA.rawCiphertextCount}`);
    log('test', 'info', `Bob raw ciphertext remaining: ${finalDomB.rawCiphertextCount}`);
    log('test', 'info', `Alice unexpected elements: ${JSON.stringify(finalDomA.unexpectedElements)}`);
    log('test', 'info', `Bob unexpected elements: ${JSON.stringify(finalDomB.unexpectedElements)}`);

    if (errors.length > 0) {
      log('test', 'info', '');
      log('test', 'info', '--- ALL ERRORS ---');
      errors.forEach((e) => log('test', 'info', `  [${e.source}] ${e.text}`));
    }

    if (warnings.length > 0) {
      log('test', 'info', '');
      log('test', 'info', '--- ALL WARNINGS ---');
      warnings.forEach((e) => log('test', 'info', `  [${e.source}] ${e.text}`));
    }

    log('test', 'info', '=================================================================');

  } finally {
    if (contextA) await contextA.close().catch(() => {});
    if (contextB) await contextB.close().catch(() => {});
    await stopServer();
  }
});
