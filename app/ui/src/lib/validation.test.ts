import { describe, expect, it } from 'vitest';
import { defaultSettings } from './api';
import { backupCountError, fontSizeError, passwordChangeError, settingsError } from './validation';

describe('fontSizeError', () => {
  it('akceptuje liczby całkowite od 9 do 32', () => {
    expect(fontSizeError(9)).toBeNull();
    expect(fontSizeError(13)).toBeNull();
    expect(fontSizeError(32)).toBeNull();
  });
  it('odrzuca wartości spoza zakresu, ułamki i nie-liczby', () => {
    const msg = 'Rozmiar czcionki terminala musi być liczbą od 9 do 32.';
    for (const v of [8, 33, 12.5, NaN, null, undefined, '12', '']) {
      expect(fontSizeError(v)).toBe(msg);
    }
  });
});

describe('passwordChangeError', () => {
  it('brak zmiany hasła to brak błędu', () => {
    expect(passwordChangeError('', '', '')).toBeNull();
  });
  it('wymaga obecnego hasła', () => {
    expect(passwordChangeError('', 'dlugie-haslo', 'dlugie-haslo')).toBe('Podaj obecne hasło.');
  });
  it('wymaga co najmniej 8 znaków w nowym haśle', () => {
    expect(passwordChangeError('stare', 'abcdefg', 'abcdefg')).toBe('Nowe hasło musi mieć co najmniej 8 znaków.');
    expect(passwordChangeError('stare', 'abcdefgh', 'abcdefgh')).toBeNull();
    expect(passwordChangeError('stare', 'abcdefghi', 'abcdefghi')).toBeNull();
  });
  it('liczy znaki spoza BMP jako jeden znak', () => {
    const sevenEmoji = '😀'.repeat(7);
    const eightEmoji = '😀'.repeat(8);
    expect(passwordChangeError('stare', sevenEmoji, sevenEmoji)).toBe('Nowe hasło musi mieć co najmniej 8 znaków.');
    expect(passwordChangeError('stare', eightEmoji, eightEmoji)).toBeNull();
  });
  it('wykrywa różne nowe hasła', () => {
    expect(passwordChangeError('stare', 'nowe-haslo-1', 'nowe-haslo-2')).toBe('Nowe hasła nie są takie same.');
  });
  it('poprawna zmiana daje null', () => {
    expect(passwordChangeError('stare', 'nowe-haslo-1', 'nowe-haslo-1')).toBeNull();
  });
});

describe('backupCountError', () => {
  it('akceptuje 1-20', () => {
    expect(backupCountError(1)).toBeNull();
    expect(backupCountError(20)).toBeNull();
  });
  it('odrzuca resztę', () => {
    for (const v of [0, 21, 2.5, NaN, null, '5']) expect(backupCountError(v)).toBe('Liczba kopii zapasowych musi być liczbą od 1 do 20.');
  });
});

describe('settingsError', () => {
  const ok = () => defaultSettings();
  it('domyślne ustawienia są poprawne, granice przechodzą', () => {
    expect(settingsError(ok())).toBeNull();
    expect(settingsError({ ...ok(), terminal_scrollback: 0, ssh_keepalive_secs: 3600, auto_lock_minutes: 1440 })).toBeNull();
    expect(settingsError({ ...ok(), terminal_scrollback: 100000 })).toBeNull();
  });
  it('wskazuje kategorię błędu', () => {
    expect(settingsError({ ...ok(), terminal_font_size: 8 })?.category).toBe('terminal');
    expect(settingsError({ ...ok(), ssh_term: 'x y' })?.category).toBe('terminal');
    expect(settingsError({ ...ok(), ssh_term: '' })?.category).toBe('terminal');
    expect(settingsError({ ...ok(), terminal_scrollback: 100001 })?.category).toBe('terminal');
    expect(settingsError({ ...ok(), ssh_keepalive_secs: 3601 })?.category).toBe('sessions');
    expect(settingsError({ ...ok(), auto_lock_minutes: 1441 })?.category).toBe('security');
    expect(settingsError({ ...ok(), auto_lock_minutes: 1441 })?.message).toBe('Czas automatycznej blokady musi być liczbą od 0 do 1440 minut.');
  });
});
