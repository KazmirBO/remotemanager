import { Channel, invoke } from '@tauri-apps/api/core';
import { createAcker } from './sshAck';

export type Protocol = 'ssh' | 'rdp';
export type Id = string;

export type RdpProfile = 'fast' | 'slow';
export type RdpKeys = 'never' | 'fullscreen' | 'always';

/** Przekierowanie czytników kart do sesji RDP: wyłączone, pod prawdziwymi albo neutralnymi nazwami. */
export type RdpSmartcard = 'off' | 'on' | 'neutral';

export interface FieldsIo {
  port: number | null;
  username: string | null;
  domain: string | null;
  jump_host: Id | null;
  terminal_scheme: string | null;
  rdp_multimon: boolean | null;
  rdp_kerberos: boolean | null;
  rdp_kdc: string | null;
  /** Profil łącza RDP; `null` dziedziczy z katalogu albo z ustawień. */
  rdp_profile: RdpProfile | null;
  /** Przekierowanie kluczy bezpieczeństwa (WebAuthn) do sesji RDP; `null` dziedziczy z katalogu. */
  rdp_webauthn: boolean | null;
  /** Przekierowanie czytników kart inteligentnych do sesji RDP; `null` dziedziczy z katalogu. */
  rdp_smartcard: RdpSmartcard | null;
  has_password: boolean;
  /** Tylko wejście. */
  password?: string | null;
  clear_password?: boolean;
  /** Ścieżka do pliku klucza prywatnego; `null` dziedziczy z katalogu. */
  ssh_key_path: string | null;
  /** Typ terminala zgłaszany serwerowi SSH (TERM); `null` dziedziczy, a bez ustawienia `xterm-256color`. */
  ssh_term: string | null;
  /** Starsze algorytmy SSH dla starych serwerów; `null` dziedziczy z katalogu. */
  ssh_legacy: boolean | null;
  /** Tylko wyjście: klucz zapisany w pliku hostów na tym poziomie. */
  has_ssh_key: boolean;
  ssh_key_algorithm: string | null;
  ssh_key_fingerprint: string | null;
  /** Tylko wejście: tekst klucza do importu. */
  ssh_key?: string | null;
  /** Tylko wejście: hasło importowanego klucza. */
  ssh_key_passphrase?: string | null;
  clear_ssh_key?: boolean;
}

export interface FolderView { id: Id; name: string; parent: Id | null; fields: FieldsIo }
export interface HostView {
  id: Id; name: string; address: string; protocol: Protocol; folder: Id | null;
  favorite: boolean; notes: string; fields: FieldsIo;
}
export interface Settings {
  theme: 'dark' | 'light' | 'system';
  terminal_font_size: number;
  terminal_scheme: string;
  shortcuts: Record<string, string>;
  /** Domyślny profil łącza RDP, gdy żaden poziom drzewa go nie ustawia. */
  rdp_profile: RdpProfile;
  /** Kiedy sesja RDP przechwytuje klawisze (skróty aplikacji i systemu). */
  rdp_keys: RdpKeys;
}
export interface DocView { folders: FolderView[]; hosts: HostView[]; settings: Settings; trusted_count: number }

export type VaultState = 'missing' | 'locked' | 'unlocked';

export interface TrustRequest {
  id: string; protocol: Protocol; host: string; port: number; algorithm: string; fingerprint: string; previous: string | null;
}

export type ShellControl = { t: 'exit'; code: number } | { t: 'closed' };

export const emptyFields = (): FieldsIo => ({
  port: null, username: null, domain: null, jump_host: null,
  terminal_scheme: null, rdp_multimon: null, rdp_kerberos: null, rdp_kdc: null, rdp_profile: null, rdp_webauthn: null, rdp_smartcard: null, has_password: false,
  ssh_key_path: null, ssh_term: null, ssh_legacy: null, has_ssh_key: false, ssh_key_algorithm: null, ssh_key_fingerprint: null,
});

/** Backend zwraca błędy jako tekst; sprowadzamy wszystko do `string`. */
const call = async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw typeof e === 'string' ? e : e instanceof Error ? e.message : String(e);
  }
};

export type SyncStatus = 'brak_pliku' | 'aktualny' | 'lokalne_zmiany' | 'zdalne_zmiany' | 'konflikt';
export interface SyncView { folder: string | null; status: SyncStatus | null; error: string | null }
export interface BackupInfo { n: number; modified: number; size: number }
export interface LocalConfig { log_sessions: boolean; rdp_clipboard: boolean; logs_dir: string }
export interface LinkView {
  protocol: Protocol; host: string; port: number | null; username: string | null;
  /** Port z linku albo domyślny dla protokołu (rozstrzyga backend). */
  resolved_port: number;
  domain: string | null; matching_host: Id | null;
}

export const api = {
  vaultState: () => call<VaultState>('vault_state'),
  createVault: (password: string) => call<void>('create_vault', { password }),
  unlock: (password: string) => call<void>('unlock', { password }),
  lock: () => call<void>('lock'),
  changePassword: (old: string, nw: string) => call<void>('change_password', { old, new: nw }),
  getDoc: () => call<DocView>('get_doc'),
  saveFolder: (input: { id: Id | null; name: string; parent: Id | null; fields: FieldsIo }) =>
    call<Id>('save_folder', { input }),
  saveHost: (input: {
    id: Id | null; name: string; address: string; protocol: Protocol; folder: Id | null;
    notes: string; fields: FieldsIo;
  }) => call<Id>('save_host', { input }),
  deleteFolder: (id: Id) => call<number>('delete_folder', { id }),
  deleteHost: (id: Id) => call<void>('delete_host', { id }),
  moveHost: (id: Id, folder: Id | null) => call<void>('move_host', { id, folder }),
  moveFolder: (id: Id, parent: Id | null) => call<void>('move_folder', { id, parent }),
  setFavorite: (id: Id, favorite: boolean) => call<void>('set_favorite', { id, favorite }),
  saveSettings: (settings: Settings) => call<void>('save_settings', { settings }),
  syncStatus: () => call<SyncView>('sync_status'),
  syncSetFolder: (folder: string | null) => call<SyncView>('sync_set_folder', { folder }),
  syncRun: (keep?: 'local' | 'remote') => call<{ view: SyncView; locked: boolean }>('sync_run', { keep: keep ?? null }),
  listBackups: () => call<BackupInfo[]>('list_backups'),
  restoreBackup: (n: number, password: string) => call<void>('restore_backup', { n, password }),
  getDiagnostics: () => call<string[]>('get_diagnostics'),
  clearDiagnostics: () => call<void>('clear_diagnostics'),
  getLocalConfig: () => call<LocalConfig>('get_local_config'),
  setRdpClipboard: (enabled: boolean) => call<void>('set_rdp_clipboard', { enabled }),
  setLogSessions: (enabled: boolean) => call<void>('set_log_sessions', { enabled }),
  resolveLink: (url: string) => call<LinkView>('resolve_link', { url }),
  takePendingLink: () => call<string | null>('take_pending_link'),
  answerTrust: (id: string, accept: boolean, remember: boolean) =>
    call<void>('answer_trust', { id, accept, remember }),
  sshResize: (id: string, cols: number, rows: number) => call<void>('ssh_resize', { id, cols, rows }),
  sshClose: (id: string) => {
    // Zamknięcie karty nie zawsze kończy się komunikatem sterującym, więc nasłuch widoczności
    // dokumentu tej sesji zdejmujemy także tutaj.
    sshStops.get(id)?.();
    sshStops.delete(id);
    return call<void>('ssh_close', { id });
  },
  sshAck: (id: string, bytes: number) => call<void>('ssh_ack', { id, bytes }),
};

/** Sprzątanie nasłuchu widoczności dokumentu dla otwartych sesji SSH (patrz `connectSsh`). */
const sshStops = new Map<string, () => void>();

/** Wywołanie z surowym ciałem i identyfikatorem sesji w nagłówku. */
export function sshWrite(id: string, data: Uint8Array): Promise<void> {
  return invoke<void>('ssh_write', data, { headers: { 'x-session': id } }).catch(() => {});
}

export async function connectSsh(
  hostId: Id, cols: number, rows: number, password: string | null, keyPassphrase: string | null,
  onData: (bytes: Uint8Array, done: () => void) => void, onControl: (c: ShellControl) => void,
): Promise<string> {
  const channel = new Channel<ArrayBuffer | ShellControl>();
  // Kontrola przepływu: backend wstrzymuje wyjście po 4 MiB niepotwierdzonych bajtów. `done` wywołuje
  // widok, gdy terminal przetworzył porcję (`term.write(dane, done)`); w ukrytym dokumencie potwierdzamy
  // od razu (patrz `sshAck.ts`). Dane mogą przyjść przed identyfikatorem sesji; licznik wtedy czeka.
  let id: string | null = null;
  const acker = createAcker(
    (bytes) => id !== null && void api.sshAck(id, bytes).catch(() => {}),
    () => document.hidden,
    SSH_ACK_BYTES,
  );
  const onVisibility = () => document.hidden && acker.hide();
  document.addEventListener('visibilitychange', onVisibility);
  const stop = () => {
    document.removeEventListener('visibilitychange', onVisibility);
    if (id !== null) sshStops.delete(id);
  };
  const data = (bytes: Uint8Array) => onData(bytes, acker.receive(bytes.length));
  channel.onmessage = (msg) => {
    if (msg instanceof ArrayBuffer) data(new Uint8Array(msg));
    else if (ArrayBuffer.isView(msg)) {
      const v = msg as ArrayBufferView;
      data(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
    }
    else if (Array.isArray(msg)) data(Uint8Array.from(msg as number[]));
    else {
      stop();
      onControl(msg as ShellControl);
    }
  };
  try {
    id = await call<string>('connect_ssh', { hostId, cols, rows, password, keyPassphrase, onEvent: channel });
  } catch (e) {
    stop();
    throw e;
  }
  sshStops.set(id, stop);
  acker.ready();
  return id;
}
/** Co tyle przetworzonych bajtów wyjścia SSH interfejs wysyła potwierdzenie (okno backendu to 4 MiB). */
const SSH_ACK_BYTES = 256 * 1024;

export type RdpControl =
  | { t: 'connected'; width: number; height: number }
  | { t: 'resized'; width: number; height: number }
  | { t: 'error'; message: string }
  | { t: 'notice'; message: string }
  | { t: 'pointer'; width: number; height: number; hot_x: number; hot_y: number; rgba: number[] }
  | { t: 'pointer_default' }
  | { t: 'pointer_hidden' }
  | { t: 'closed'; reason: string };

export type RdpCommand =
  | { t: 'mouse_move'; x: number; y: number }
  | { t: 'mouse_button'; button: number; down: boolean }
  | { t: 'wheel'; vertical: boolean; delta: number }
  | { t: 'key'; scancode: number; extended: boolean; down: boolean }
  | { t: 'ctrl_alt_del' }
  | { t: 'resize'; width: number; height: number };

/** Obraz RDP: 8 bajtów nagłówka (x, y, szerokość, wysokość jako u16 LE), potem RGBA. */
export async function connectRdp(
  hostId: Id, width: number, height: number, password: string | null,
  onImage: (x: number, y: number, w: number, h: number, rgba: Uint8ClampedArray) => void,
  onControl: (c: RdpControl) => void,
): Promise<string> {
  const channel = new Channel<ArrayBuffer | RdpControl>();
  // Kontrola przepływu: backend wstrzymuje obraz, gdy za dużo bajtów czeka na odebranie, więc
  // potwierdzamy odebrane porcje. Obraz może przyjść przed identyfikatorem sesji; licznik wtedy czeka.
  let id: string | null = null;
  let unacked = 0;
  const ack = () => {
    if (id === null || unacked < RDP_ACK_BYTES) return;
    const bytes = unacked;
    unacked = 0;
    void call<void>('rdp_ack', { id, bytes }).catch(() => {});
  };
  channel.onmessage = (msg) => {
    if (msg instanceof ArrayBuffer) {
      const v = new DataView(msg);
      // Bajty liczymy przed rysowaniem: wyjątek w `onImage` nie może pominąć potwierdzenia.
      unacked += msg.byteLength;
      try {
        onImage(v.getUint16(0, true), v.getUint16(2, true), v.getUint16(4, true), v.getUint16(6, true),
          new Uint8ClampedArray(msg, 8));
      } finally {
        ack();
      }
    } else {
      onControl(msg as RdpControl);
    }
  };
  id = await call<string>('connect_rdp', { hostId, width, height, password, onEvent: channel });
  ack();
  return id;
}
/** Co tyle odebranych bajtów obrazu interfejs wysyła potwierdzenie (okno backendu to 64 MiB). */
const RDP_ACK_BYTES = 1024 * 1024;

export const rdpSend = (id: string, cmd: RdpCommand) => call<void>('rdp_send', { id, cmd }).catch(() => {});
export const rdpClipboardFocus = (id: string, focused: boolean) =>
  call<void>('rdp_clipboard_focus', { id, focused }).catch(() => {});
export const rdpClose = (id: string) => call<void>('rdp_close', { id });

/** Skrót zwalniający przechwycone klawisze: scancode z `scancodes.ts` i modyfikatory. */
export interface ReleaseCombo { scancode: number; extended: boolean; ctrl: boolean; alt: boolean; shift: boolean; meta: boolean }
/** Włącza albo wyłącza przechwytywanie klawiszy; `system` mówi, czy przejęto też klawisze systemowe.
 * Błąd wywołania (np. sesja już nie istnieje) daje `null`. */
export const rdpGrabKeys = (id: string, on: boolean, release: ReleaseCombo | null) =>
  call<{ system: boolean }>('rdp_grab_keys', { id, on, release }).catch(() => null);
