import type { Settings } from './api';

export interface ActionDef { id: string; label: string; default: string }

export const ACTIONS: ActionDef[] = [
  { id: 'quick_connect', label: 'Szybkie łączenie', default: 'Ctrl+K' },
  { id: 'close_tab', label: 'Zamknij kartę', default: 'Ctrl+Shift+W' },
  { id: 'new_host', label: 'Nowy host', default: 'Ctrl+Shift+N' },
  { id: 'next_tab', label: 'Następna karta', default: 'Ctrl+PageDown' },
  { id: 'prev_tab', label: 'Poprzednia karta', default: 'Ctrl+PageUp' },
  { id: 'lock', label: 'Zablokuj plik', default: 'Ctrl+Shift+L' },
  { id: 'settings', label: 'Ustawienia', default: 'Ctrl+,' },
];

interface KeyLike {
  ctrlKey: boolean; metaKey: boolean; altKey: boolean; shiftKey: boolean; code: string;
  getModifierState?: (key: string) => boolean;
}

const MODIFIER_CODES = /^(Control|Shift|Alt|Meta|OS)(Left|Right)?$/;

function keyName(code: string): string | null {
  if (MODIFIER_CODES.test(code)) return null;
  if (/^Key[A-Z]$/.test(code)) return code.slice(3);
  if (/^Digit\d$/.test(code)) return code.slice(5);
  const punct: Record<string, string> = { Comma: ',', Period: '.', Slash: '/', Semicolon: ';', Quote: "'", Minus: '-', Equal: '=' };
  return punct[code] ?? code;
}

/** Kombinacja w postaci kanonicznej, np. "Ctrl+Shift+W"; `null`, gdy naciśnięto sam modyfikator. */
export function comboFromEvent(e: KeyLike): string | null {
  const key = keyName(e.code);
  if (!key) return null;
  const parts: string[] = [];
  if (e.ctrlKey) parts.push('Ctrl');
  if (e.altKey) parts.push('Alt');
  if (e.shiftKey) parts.push('Shift');
  if (e.metaKey) parts.push('Meta');
  parts.push(key);
  return parts.join('+');
}

/** Skrót musi mieć Ctrl, Alt albo Meta (albo być klawiszem funkcyjnym), inaczej zabrałby zwykłe pisanie.
 * Ctrl+Alt (bez Meta) jest odrzucane, bo na Windows tak wygląda AltGr: na polskiej klawiaturze
 * Ctrl+Alt+L to zwykłe "ł". */
export function validCombo(combo: string): boolean {
  const parts = combo.split('+');
  const key = parts[parts.length - 1];
  const mods = parts.slice(0, -1);
  if (mods.includes('Ctrl') && mods.includes('Alt') && !mods.includes('Meta')) return false;
  return parts.length >= 2 ? mods.some((m) => m === 'Ctrl' || m === 'Alt' || m === 'Meta') : /^F\d{1,2}$/.test(key);
}

export function binding(settings: Settings | undefined, id: string): string {
  const custom = settings?.shortcuts?.[id];
  return custom || ACTIONS.find((a) => a.id === id)!.default;
}

/** Akcja przypisana do zdarzenia klawiatury albo `null`. */
export function matchAction(settings: Settings | undefined, e: KeyLike): string | null {
  // AltGr wpisuje znaki (ą, ę, ł...), nawet jeśli przeglądarka zgłasza je jako Ctrl+Alt.
  if (e.getModifierState?.('AltGraph')) return null;
  const combo = comboFromEvent(e);
  if (!combo) return null;
  return ACTIONS.find((a) => binding(settings, a.id) === combo)?.id ?? null;
}

/** Id innej akcji, która już używa tej kombinacji. */
export function findConflict(settings: Settings | undefined, id: string, combo: string): string | null {
  return ACTIONS.find((a) => a.id !== id && binding(settings, a.id) === combo)?.id ?? null;
}

/** Czy akcja działa, gdy otwarte jest okno modalne. Tylko blokada pliku, bo to akcja bezpieczeństwa.
 * Pozostałe skróty zamieniłyby okno z niezapisanym formularzem albo zmieniły karty schowane pod oknem. */
export function allowedWithModal(action: string): boolean {
  return action === 'lock';
}
