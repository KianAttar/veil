# Chrome Web Store Listing

## Short Description (132 chars max)

End-to-end encryption for any web messenger. No accounts, no servers. Keys live in memory only. Open source.

## Detailed Description

Veil adds end-to-end encryption to any web messenger — WhatsApp Web, Telegram Web, Facebook Messenger, or any chat that runs in your browser.

The platform never sees your messages. Only encrypted text leaves your browser.

HOW IT WORKS

1. One person clicks "Start Session" and an invite code is sent through the chat
2. The other person opens Veil, and the extension automatically detects the invite and replies
3. Both sides derive a shared secret — every message is now encrypted with AES-256-GCM before it enters the chat

No extra apps. No sign-ups. Just install and go.

SECURITY

• Fresh ECDH P-256 key pairs generated per session
• Shared secrets derived with HKDF
• Messages encrypted with AES-256-GCM
• Session fingerprint for manual verification
• In-band and server-based verification to detect man-in-the-middle attacks
• End-session signal wipes all keys on both sides simultaneously

PRIVACY

• No accounts — no email, no phone number, nothing
• Keys exist in RAM only (chrome.storage.session) — close the browser and they're gone
• No analytics, no telemetry, no data collection of any kind
• Fully open source: https://github.com/KianAttar/veil

WHAT VEIL CANNOT PROTECT

Veil encrypts message content in transit and at rest on the platform's servers. It cannot protect against:
• Device-level compromise (malware, spyware, keyloggers)
• Physical access to an unlocked device
• Metadata (who you talk to, when, how often)
• Screenshots or screen recording

SETUP

First time on a site, click "Set up for this site" to teach Veil where the input box and send button are. After that, encryption is automatic.

Supports English and Persian (فارسی).

Website: https://veil.kiancode.dev
Source: https://github.com/KianAttar/veil
Support: support@kiancode.dev

## Category

Communication

## Language

English

## Privacy Practices

### Single Purpose Description

Veil encrypts and decrypts messages in the browser using end-to-end encryption, so that the messaging platform only sees ciphertext.

### Permissions Justification

- **storage**: Store language preference and per-site input detection settings locally
- **activeTab**: Read and modify chat messages on the active tab to encrypt/decrypt them
- **tabs**: Identify the active tab's URL to route messages between popup and content script

### Data Usage Disclosure

- Veil does NOT collect or transmit any user data
- Veil does NOT use remote code
- Encryption keys are stored in session-only memory and never written to disk
- The only network request is an optional fingerprint verification ping to verify.veil.kiancode.dev (no user data is sent — only a public key hash)
