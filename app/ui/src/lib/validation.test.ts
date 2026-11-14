import { describe, expect, it } from 'vitest';
import { fontSizeError, passwordChangeError } from './validation';

describe('fontSizeError', () => {
  it('akceptuje liczby całkowite od 9 do 32', () => {
    expect(fontSizeError(9)).toBeNull();
    expect(fontSizeError(13)).toBeNull();
    expect(fontSizeError(32)).toBeNull();
  });
  it('odrzuca wartości spoza zakresu, ułamki i nie-liczby', () => {
    const msg = 'Rozmiar czcionki terminala musi być liczbą całkowitą od 9 do 32.';
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
