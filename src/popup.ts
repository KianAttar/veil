// Veil — Popup panel logic
// Reads session state, sends commands to content script, displays status.
// No crypto logic here — content.ts handles everything.

import { t, setLang, getLang } from './i18n';
import type { Language, StringKey } from './types';

type VerifyStatus = 'pending' | 'verified' | 'failed' | 'error';

interface SessionState {
  veil_handshake_state?: 'idle' | 'invited' | 'established';
  veil_public_key?: string;
  veil_their_public_key?: string;
  veil_fingerprint?: string;
  inBandVerify?: VerifyStatus;
  serverVerify?: VerifyStatus;
  serverVerifyError?: string;
}

function sendToContent(msg: Record<string, unknown>): void {
  chrome.runtime.sendMessage({ target: 'content', ...msg });
}

function getHostname(): Promise<string> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'GET_TAB_HOSTNAME' }, (resp) => {
      resolve(resp?.hostname ?? '');
    });
  });
}

function getSessionState(): Promise<SessionState> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { target: 'content', type: 'GET_SESSION_STATE' },
      (response) => {
        if (!response) {
          resolve({});
          return;
        }
        resolve({
          veil_handshake_state: response.handshakeState ?? 'idle',
          veil_fingerprint: response.fingerprint ?? undefined,
          veil_public_key: response.myPublicKeyBase64 ?? undefined,
          veil_their_public_key: response.theirPublicKeyBase64 ?? undefined,
          inBandVerify: response.inBandVerify ?? 'pending',
          serverVerify: response.serverVerify ?? 'pending',
          serverVerifyError: response.serverVerifyError ?? undefined,
        });
      },
    );
  });
}

async function isOnboarded(hostname: string): Promise<boolean> {
  if (!hostname) return false;
  return new Promise((resolve) => {
    chrome.storage.local.get([`veil_input_selector_${hostname}`], (data) => {
      resolve(!!data[`veil_input_selector_${hostname}`]);
    });
  });
}

const VERIFY_KEY_MAP: Record<VerifyStatus, StringKey> = {
  pending: 'verify_checking',
  verified: 'verify_verified',
  failed: 'verify_mismatch',
  error: 'verify_unavailable',
};

function renderVerifyStatus(el: HTMLElement, status: VerifyStatus, errorDetail?: string): void {
  el.className = `verify-status ${status}`;
  el.textContent = t(VERIFY_KEY_MAP[status]);
  if (errorDetail && (status === 'failed' || status === 'error')) {
    el.title = errorDetail;
  } else {
    el.title = '';
  }
}

/** Update all data-tip attributes with current language */
function updateTooltips(): void {
  const tipMap: Record<string, StringKey> = {
    tipStatus: 'tip_status',
    tipFingerprint: 'tip_fingerprint',
    tipInband: 'tip_inband',
    tipServer: 'tip_server',
    tipStartSession: 'tip_start_session',
    tipEndSession: 'tip_end_session',
    tipSetup: 'tip_setup',
    tipReconfigure: 'tip_reconfigure',
    tipLanguage: 'tip_language',
  };
  for (const [id, key] of Object.entries(tipMap)) {
    const el = document.getElementById(id);
    if (el) el.setAttribute('data-tip', t(key));
  }
}

async function render(): Promise<void> {
  const hostname = await getHostname();
  const state = await getSessionState();
  const onboarded = await isOnboarded(hostname);
  const handshakeState = state.veil_handshake_state ?? 'idle';

  // Hostname
  const hostnameEl = document.getElementById('hostname')!;
  hostnameEl.textContent = hostname || 'No active tab';

  // Status
  const dot = document.getElementById('statusDot')!;
  const statusText = document.getElementById('statusText')!;
  dot.className = `status-dot ${handshakeState}`;

  if (handshakeState === 'established') {
    statusText.textContent = t('popup_connected');
  } else if (handshakeState === 'invited') {
    statusText.textContent = t('popup_waiting_response');
  } else {
    statusText.textContent = t('popup_no_session');
  }

  // Fingerprint + verification
  const fpEl = document.getElementById('fingerprint')!;
  const fpLabel = document.getElementById('fingerprintLabel')!;
  const fpLabelText = document.getElementById('fingerprintLabelText')!;
  const verifySection = document.getElementById('verifySection')!;

  if (state.veil_fingerprint && handshakeState === 'established') {
    fpEl.textContent = state.veil_fingerprint;
    fpEl.classList.remove('hidden');
    fpLabel.classList.remove('hidden');
    verifySection.classList.remove('hidden');

    fpLabelText.textContent = t('popup_compare_peer');

    // Verification labels
    document.getElementById('inBandLabel')!.textContent = t('popup_inband');
    document.getElementById('serverLabel')!.textContent = t('popup_server');

    const inBandEl = document.getElementById('inBandStatus')!;
    renderVerifyStatus(inBandEl, state.inBandVerify ?? 'pending');

    const serverEl = document.getElementById('serverStatus')!;
    renderVerifyStatus(serverEl, state.serverVerify ?? 'pending', state.serverVerifyError);
  } else {
    fpEl.classList.add('hidden');
    fpLabel.classList.add('hidden');
    verifySection.classList.add('hidden');
  }

  // Buttons
  const btnStart = document.getElementById('btnStartSession')!;
  const btnEnd = document.getElementById('btnEndSession')!;
  const btnSetup = document.getElementById('btnSetup')!;
  const btnReconfigure = document.getElementById('btnReconfigure')!;
  const setupNeeded = document.getElementById('setupNeeded')!;

  // Update button labels
  document.getElementById('btnStartLabel')!.textContent = t('start_session');
  document.getElementById('btnEndLabel')!.textContent = t('end_session');
  document.getElementById('btnSetupLabel')!.textContent = t('popup_setup_site');
  document.getElementById('btnReconfigureLabel')!.textContent = t('popup_reconfigure');
  setupNeeded.textContent = t('popup_setup_needed');

  if (handshakeState === 'established') {
    btnStart.classList.add('hidden');
    btnEnd.classList.remove('hidden');
    btnSetup.classList.add('hidden');
    btnReconfigure.classList.remove('hidden');
    setupNeeded.classList.add('hidden');
  } else if (handshakeState === 'invited') {
    btnStart.classList.add('hidden');
    btnEnd.classList.remove('hidden');
    btnSetup.classList.add('hidden');
    btnReconfigure.classList.add('hidden');
    setupNeeded.classList.add('hidden');
  } else {
    btnEnd.classList.add('hidden');

    if (onboarded) {
      btnStart.classList.remove('hidden');
      (btnStart as HTMLButtonElement).disabled = false;
      btnSetup.classList.add('hidden');
      btnReconfigure.classList.remove('hidden');
      setupNeeded.classList.add('hidden');
    } else {
      btnStart.classList.remove('hidden');
      (btnStart as HTMLButtonElement).disabled = true;
      btnSetup.classList.remove('hidden');
      btnReconfigure.classList.add('hidden');
      setupNeeded.classList.remove('hidden');
    }
  }

  // Language buttons
  const lang = getLang();
  document.getElementById('langEn')!.classList.toggle('active', lang === 'en');
  document.getElementById('langFa')!.classList.toggle('active', lang === 'fa');
  document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
  document.documentElement.lang = lang === 'fa' ? 'fa' : 'en';

  // Update all tooltips for current language
  updateTooltips();
}

function bindEvents(): void {
  document.getElementById('btnStartSession')!.addEventListener('click', () => {
    sendToContent({ type: 'START_SESSION' });
    window.close();
  });

  document.getElementById('btnEndSession')!.addEventListener('click', () => {
    sendToContent({ type: 'END_SESSION' });
    window.close();
  });

  document.getElementById('btnSetup')!.addEventListener('click', () => {
    sendToContent({ type: 'START_ONBOARDING' });
    window.close();
  });

  document.getElementById('btnReconfigure')!.addEventListener('click', () => {
    sendToContent({ type: 'START_ONBOARDING' });
    window.close();
  });

  document.querySelectorAll<HTMLButtonElement>('.lang-btn[data-lang]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const lang = btn.dataset.lang as Language;
      setLang(lang);
      chrome.storage.local.set({ veil_lang: lang });
      sendToContent({ type: 'SET_LANGUAGE', lang });
      render();
    });
  });
}

async function init(): Promise<void> {
  chrome.storage.local.get(['veil_lang'], (data) => {
    if (data.veil_lang) {
      setLang(data.veil_lang as Language);
    }
    render();
  });

  bindEvents();
}

init();
