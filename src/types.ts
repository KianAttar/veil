// Veil — Shared types

export interface HandshakeData {
  publicKey: string;
  signature: string;
}

export interface ScannedEncrypted {
  type: 'encrypted';
  payload: string;
}

export interface ScannedHandshake {
  type: 'handshake';
  publicKey: string;
  signature: string;
}

export interface ScannedVerify {
  type: 'verify';
  payload: string;
}

export type ScannedItem = ScannedEncrypted | ScannedHandshake | ScannedVerify;

export interface ChatMessage {
  sender: 'you' | 'them' | 'system';
  text: string;
}

export type Language = 'en' | 'fa';

export type PanelId =
  | 'panelLang'
  | 'panelNoSession'
  | 'panelHandshake'
  | 'panelHandshakeReceived'
  | 'panelSession'
  | 'panelSettings'
  | 'panelCopyFallback'
  | 'panelOnboarding';

export type OnboardingMode = 'input' | 'send';

export type StringKey =
  | 'app_name' | 'start_session' | 'complete_handshake' | 'waiting' | 'verified'
  | 'no_session' | 'send_encrypted' | 'end_session' | 'settings' | 'copy' | 'copied'
  | 'cancel' | 'type_message' | 'send_invite' | 'copy_invite' | 'waiting_reply'
  | 'manual_tools' | 'paste_decrypt' | 'decrypt' | 'onboarding_input' | 'onboarding_send'
  | 'onboarding_done' | 'onboarding_reset' | 'language' | 'secure' | 'fingerprint'
  | 'fingerprint_match' | 'fingerprint_mismatch' | 'compare_fingerprint' | 'you' | 'them'
  | 'session_ended' | 'copy_fallback' | 'what_veil_does' | 'what_veil_cannot'
  | 'hygiene_note' | 'first_launch_welcome' | 'choose_language' | 'handshake_received'
  | 'accept_handshake' | 'step1_title' | 'step1_desc' | 'step2_title' | 'step2_desc'
  | 'step3_title' | 'step3_desc' | 'create_invite' | 'i_received_invite'
  | 'paste_invite_prompt' | 'paste_here' | 'connect' | 'status_generating'
  | 'status_connected' | 'status_waiting' | 'how_it_works' | 'how_it_works_desc'
  | 'or_paste_reply' | 'paste_reply_here' | 'submit_reply' | 'paste_incoming'
  | 'paste_incoming_here' | 'decrypt_incoming';
