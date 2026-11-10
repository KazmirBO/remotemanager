import { api, type DocView, type SyncView, type HostView, type Id, type Protocol, type Settings, type VaultState } from './api';

export interface Tab {
  id: string;
  hostId: Id;
  protocol: Protocol;
  title: string;
  /** Zwiększany przy ponownym łączeniu, żeby odtworzyć terminal. */
  generation: number;
}

export interface PasswordPrompt {
  title: string;
  reason: string;
  resolve: (password: string | null) => void;
}

export interface Notice {
  time: number;
  text: string;
}

export const ui = $state({
  history: [] as Notice[],
  sync: null as SyncView | null,
  passwordPrompt: null as PasswordPrompt | null,
  phase: 'loading' as 'loading' | VaultState,
  doc: null as DocView | null,
  tabs: [] as Tab[],
  activeTab: null as string | null,
  notice: null as string | null,
});

let noticeTimer: ReturnType<typeof setTimeout> | undefined;
export function notify(message: string) {
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

export async function lockVault() {
  for (const t of ui.tabs) closeTabNow(t.id);
  await api.lock();
  ui.doc = null;
  ui.phase = 'locked';
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

/** Pyta o hasło do jednej sesji (nie jest zapisywane). Zwraca `null`, gdy użytkownik anuluje. */
export function requestPassword(title: string, reason: string): Promise<string | null> {
  return new Promise((resolve) => {
    ui.passwordPrompt = {
      title,
      reason,
      resolve: (pw) => {
        ui.passwordPrompt = null;
        resolve(pw);
      },
    };
  });
}

/** Odpowiedź backendu "NEEDS_PASSWORD:<powód>" oznacza, że trzeba zapytać o hasło i ponowić próbę. */
export function needsPassword(error: unknown): string | null {
  const m = String(error);
  return m.startsWith('NEEDS_PASSWORD:') ? m.slice('NEEDS_PASSWORD:'.length) : null;
}

export async function refreshSync() {
  try {
    ui.sync = await api.syncStatus();
  } catch {
    ui.sync = null;
  }
}

/** Po pobraniu zdalnej wersji plik jest zablokowany: zamykamy karty i wracamy do odblokowania. */
export function lockedBySync() {
  for (const t of [...ui.tabs]) closeTabNow(t.id);
  ui.doc = null;
  ui.phase = 'locked';
}
