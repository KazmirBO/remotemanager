import type { Protocol } from './api';

export type HostTab = 'general' | 'login' | 'connection' | 'terminal' | 'redirects';

export const TAB_LABELS: Record<HostTab, string> = {
  general: 'Ogólne',
  login: 'Logowanie',
  connection: 'Połączenie',
  terminal: 'Terminal',
  redirects: 'Przekierowania',
};

/** ssh: general, login, connection, terminal; rdp: general, login, connection, redirects; null (katalog): wszystkie. */
export function visibleTabs(protocol: Protocol | null): HostTab[] {
  if (protocol === 'ssh') return ['general', 'login', 'connection', 'terminal'];
  if (protocol === 'rdp') return ['general', 'login', 'connection', 'redirects'];
  return ['general', 'login', 'connection', 'terminal', 'redirects'];
}

// Komunikaty backendu zawierają nazwy hosta albo bastionu, więc dopasowanie idzie po początku tekstu
// (reguły `exact`), a podciąg wolno sprawdzać tylko w stałych fragmentach bez danych użytkownika.
const RULES: [HostTab, string[]][] = [
  ['connection', ['Zmiana psuje łańcuch bastionów', 'cykl w łańcuchu bastionów', 'bastion musi być']],
  ['general', ['Nazwa i adres hosta', 'Nazwa katalogu', 'przeniesienie utworzyłoby cykl katalogów']],
  ['login', ['KEY_', 'Ścieżka klucza']],
  ['terminal', ['Typ terminala', 'Rozmiar czcionki terminala', 'Polecenie po zalogowaniu']],
];

/** Zakładka pola, którego dotyczy błąd zapisu; null, gdy nie da się jej wskazać. */
export function errorTab(message: string): HostTab | null {
  for (const [tab, parts] of RULES) {
    if (parts.some((p) => message.startsWith(p))) return tab;
  }
  return null;
}
