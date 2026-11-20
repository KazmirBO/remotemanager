import type { Settings } from './api';
import type { SettingsCategory } from './settings/categories';

/** Sprawdza rozmiar czcionki terminala: liczba całkowita z zakresu 9-32, inaczej komunikat błędu. */
export function fontSizeError(value: unknown): string | null {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 9 && value <= 32) return null;
  return 'Rozmiar czcionki terminala musi być liczbą od 9 do 32.';
}

/** Sprawdza zmianę hasła głównego; gdy wszystkie pola są puste, zmiany nie ma i wynik to null. */
export function passwordChangeError(oldPw: string, newPw: string, newPw2: string): string | null {
  if (oldPw === '' && newPw === '' && newPw2 === '') return null;
  if (oldPw === '') return 'Podaj obecne hasło.';
  if ([...newPw].length < 8) return 'Nowe hasło musi mieć co najmniej 8 znaków.';
  if (newPw !== newPw2) return 'Nowe hasła nie są takie same.';
  return null;
}

const intInRange = (v: unknown, min: number, max: number) => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;

/** Sprawdza liczbę kopii zapasowych (1-20); teksty jak w backendzie. */
export function backupCountError(n: unknown): string | null {
  return intInRange(n, 1, 20) ? null : 'Liczba kopii zapasowych musi być liczbą od 1 do 20.';
}

/** Sprawdza całą kopię ustawień; zwraca pierwszy błąd i kategorię, w której leży pole. */
export function settingsError(s: Settings): { category: SettingsCategory; message: string } | null {
  const fs = fontSizeError(s.terminal_font_size);
  if (fs) return { category: 'terminal', message: fs };
  if (typeof s.ssh_term !== 'string' || !/^[A-Za-z0-9._+-]{1,64}$/.test(s.ssh_term)) {
    return { category: 'terminal', message: 'Domyślny typ terminala może mieć najwyżej 64 znaki: litery, cyfry oraz - _ . + (np. xterm-256color).' };
  }
  if (!intInRange(s.terminal_scrollback, 0, 100000)) {
    return { category: 'terminal', message: 'Historia przewijania musi być liczbą od 0 do 100000 wierszy.' };
  }
  if (!intInRange(s.ssh_keepalive_secs, 0, 3600)) {
    return { category: 'sessions', message: 'Odstęp podtrzymywania połączenia SSH musi być liczbą od 0 do 3600 sekund.' };
  }
  if (!intInRange(s.auto_lock_minutes, 0, 1440)) {
    return { category: 'security', message: 'Czas automatycznej blokady musi być liczbą od 0 do 1440 minut.' };
  }
  return null;
}
