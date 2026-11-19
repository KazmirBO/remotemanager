import { api, type DocView, type SyncView, type HostView, type Id, type Protocol, type Settings, type VaultState } from './api';
import { loadBarPos, saveBarPos, type BarPos } from './rdpBar';

export interface Tab {
  id: string;
  hostId: Id;
  protocol: Protocol;
  title: string;
  /** Zwiększany przy ponownym łączeniu, żeby odtworzyć terminal. */
  generation: number;
}

export interface PasswordPrompt {
  id: number;
  title: string;
  reason: string;
  /** Karta, która pyta; jej zamknięcie anuluje monit. */
  owner: string | null;
  resolve: (password: string | null) => void;
}

export interface Notice {
  time: number;
  text: string;
}

export const ui = $state({
  history: [] as Notice[],
  sync: null as SyncView | null,
  /** Kolejka monitów o hasło; pokazywany jest pierwszy. */
  passwordQueue: [] as PasswordPrompt[],
  phase: 'loading' as 'loading' | VaultState,
  doc: null as DocView | null,
  tabs: [] as Tab[],
  activeTab: null as string | null,
  /** Host do pokazania i zaznaczenia w drzewie (np. po otwarciu linku); drzewo zeruje to pole. */
  reveal: null as Id | null,
  notice: null as string | null,
  noticeError: false,
  /** Miejsce panelu z przyciskami w widoku RDP, wspólne dla wszystkich kart. */
  rdpBar: loadBarPos(),
});

/** Ustawia miejsce panelu sesji RDP i zapamiętuje je na tej maszynie. */
export function setRdpBar(pos: BarPos) {
  ui.rdpBar = pos;
  saveBarPos(pos);
}

let noticeTimer: ReturnType<typeof setTimeout> | undefined;
/** Powiadomienie w dymku i w historii; `error` zmienia ikonę na ostrzeżenie. */
export function notify(message: string, error = false) {
  ui.noticeError = error;
  ui.history.unshift({ time: Date.now(), text: message });
  if (ui.history.length > 50) ui.history.pop();
  ui.notice = message;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => (ui.notice = null), 6000);
}

export function applyTheme(settings: Settings | undefined) {
  const mode = settings?.theme ?? 'system';
  const light = mode === 'light' || (mode === 'system' && matchMedia('(prefers-color-scheme: light)').matches);
  if (light) document.documentElement.dataset.theme = 'light';
  else delete document.documentElement.dataset.theme;
}

export async function refresh() {
  ui.doc = await api.getDoc();
  applyTheme(ui.doc.settings);
  void refreshSync();
}

export async function init() {
  ui.phase = await api.vaultState();
  if (ui.phase === 'unlocked') await refresh();
}

export async function afterUnlock() {
  await refresh();
  ui.phase = 'unlocked';
}

/** Czy jest otwarte okno modalne. Sesja, która właśnie się połączyła, nie zabiera mu wtedy fokusu
 * (inaczej np. wpisywane hasło trafiłoby do zdalnej powłoki). */
export function modalOpen(): boolean {
  return document.querySelector('[role="dialog"][aria-modal="true"]') !== null;
}

/** Stan interfejsu po blokadzie pliku (z przycisku, skrótu, zasobnika albo po pobraniu zdalnej wersji). */
export function onLocked() {
  ui.tabs = [];
  ui.activeTab = null;
  cancelPasswordPrompts();
  ui.doc = null;
  ui.phase = 'locked';
}

export async function lockVault() {
  onLocked();
  await api.lock();
}

export function host(id: Id): HostView | undefined {
  return ui.doc?.hosts.find((h) => h.id === id);
}

export function openHost(h: HostView) {
  const same = ui.tabs.filter((t) => t.hostId === h.id).length;
  const id = crypto.randomUUID();
  ui.tabs.push({ id, hostId: h.id, protocol: h.protocol, title: same ? `${h.name} (${same + 1})` : h.name, generation: 0 });
  ui.activeTab = id;
}

function closeTabNow(id: string) {
  const i = ui.tabs.findIndex((t) => t.id === id);
  if (i < 0) return;
  ui.tabs.splice(i, 1);
  if (ui.activeTab === id) ui.activeTab = ui.tabs[Math.min(i, ui.tabs.length - 1)]?.id ?? null;
}
export const closeTab = closeTabNow;

export function reconnect(id: string) {
  const t = ui.tabs.find((x) => x.id === id);
  if (t) t.generation += 1;
}

/** Pyta o hasło do jednej sesji (nie jest zapisywane). Zwraca `null`, gdy użytkownik anuluje
 * albo karta `owner` zostanie zamknięta. Kolejne monity czekają w kolejce, żaden nie ginie. */
export function requestPassword(title: string, reason: string, owner: string | null = null): Promise<string | null> {
  return new Promise((resolve) => {
    const id = ++promptSeq;
    ui.passwordQueue.push({
      id,
      title,
      reason,
      owner,
      resolve: (pw) => {
        const i = ui.passwordQueue.findIndex((p) => p.id === id);
        if (i < 0) return; // już rozwiązany
        ui.passwordQueue.splice(i, 1);
        resolve(pw);
      },
    });
  });
}
let promptSeq = 0;

/** Anuluje monity danej karty (albo wszystkie, gdy `owner` nie jest podany). */
export function cancelPasswordPrompts(owner?: string) {
  for (const p of [...ui.passwordQueue]) {
    if (owner === undefined || p.owner === owner) p.resolve(null);
  }
}

/** Odpowiedź backendu "NEEDS_PASSWORD:<powód>" oznacza, że trzeba zapytać o hasło i ponowić próbę. */
export function needsPassword(error: unknown): string | null {
  const m = String(error);
  return m.startsWith('NEEDS_PASSWORD:') ? m.slice('NEEDS_PASSWORD:'.length) : null;
}

/** "NEEDS_KEY_PASSPHRASE:<powód>": klucz ze ścieżki wymaga hasła (także po złym haśle). */
export function needsKeyPassphrase(error: unknown): string | null {
  const m = String(error);
  return m.startsWith('NEEDS_KEY_PASSPHRASE:') ? m.slice('NEEDS_KEY_PASSPHRASE:'.length) : null;
}

/** Błąd importu klucza przy zapisie: `needsPassphrase` = pokaż pole hasła klucza. */
export function keyImportError(error: unknown): { message: string; needsPassphrase: boolean } | null {
  const m = String(error);
  for (const [prefix, needsPassphrase] of [['KEY_NEEDS_PASSPHRASE:', true], ['KEY_BAD_PASSPHRASE:', true], ['KEY_INVALID:', false]] as const) {
    if (m.startsWith(prefix)) return { message: m.slice(prefix.length), needsPassphrase };
  }
  return null;
}

export async function refreshSync() {
  try {
    ui.sync = await api.syncStatus();
  } catch {
    ui.sync = null;
  }
}

/** Po pobraniu zdalnej wersji plik jest zablokowany: zamykamy karty i wracamy do odblokowania. */
export const lockedBySync = onLocked;
