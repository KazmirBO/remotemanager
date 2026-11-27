import { describe, expect, it } from 'vitest';
import { groupSecret, looksLikeCode, pinMode, pinReady, touchLabel, unlockStep } from './mfa';

describe('unlockStep', () => {
  it('rozpoznaje odpowiedzi backendu po przedrostku', () => {
    expect(unlockStep('NEEDS_TOTP:Podaj kod z aplikacji uwierzytelniającej.'))
      .toEqual({ kind: 'needs_code', message: 'Podaj kod z aplikacji uwierzytelniającej.' });
    expect(unlockStep('TOTP_BAD:Nieprawidłowy kod.')).toEqual({ kind: 'bad_code', message: 'Nieprawidłowy kod.' });
    expect(unlockStep('TOTP_EXPIRED:Za dużo błędnych kodów. Podaj hasło główne ponownie.'))
      .toEqual({ kind: 'start_over', message: 'Za dużo błędnych kodów. Podaj hasło główne ponownie.' });
  });
  it('rozpoznaje krok klucza sprzętowego', () => {
    expect(unlockStep('NEEDS_KEY:app')).toEqual({ kind: 'needs_key', message: 'app' });
    expect(unlockStep('NEEDS_KEY:system')).toEqual({ kind: 'needs_key', message: 'system' });
    expect(unlockStep('KEY_BAD:Nieprawidłowy PIN klucza. Pozostało prób: 7.'))
      .toEqual({ kind: 'bad_key', message: 'Nieprawidłowy PIN klucza. Pozostało prób: 7.' });
    expect(unlockStep('KEY_EXPIRED:Nieprawidłowe hasło główne albo uszkodzony plik.'))
      .toEqual({ kind: 'start_over', message: 'Nieprawidłowe hasło główne albo uszkodzony plik.' });
  });
  it('pozostałe błędy przekazuje bez zmian', () => {
    expect(unlockStep('Nieprawidłowe hasło główne albo uszkodzony plik.'))
      .toEqual({ kind: 'error', message: 'Nieprawidłowe hasło główne albo uszkodzony plik.' });
    expect(unlockStep(new Error('coś')).kind).toBe('error');
    // Przedrostek w środku tekstu nie jest odpowiedzią backendu.
    expect(unlockStep('Błąd: NEEDS_TOTP:x').kind).toBe('error');
  });
});

describe('groupSecret', () => {
  it('dzieli sekret na czwórki', () => {
    expect(groupSecret('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')).toBe('GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ');
    expect(groupSecret('ABCDE')).toBe('ABCD E');
    expect(groupSecret('AB CD')).toBe('ABCD');
    expect(groupSecret('')).toBe('');
  });
});

describe('looksLikeCode', () => {
  it('przyjmuje sześć cyfr i kod zapasowy w dowolnym zapisie', () => {
    for (const ok of ['123456', '123 456', ' 123456 ', 'AAAQE-AYEAU', 'aaaqe ayeau', 'AAAQEAYEAU']) expect(looksLikeCode(ok)).toBe(true);
  });
  it('odrzuca resztę', () => {
    for (const bad of ['', '12345', '1234567', '12345a', 'AAAQE', 'AAAQE-AYEA1', 'AAAQE-AYEAUX']) expect(looksLikeCode(bad)).toBe(false);
  });
});

describe('klucz sprzętowy', () => {
  it('tryb PIN-u: nieznana wartość to pole w programie', () => {
    expect(pinMode('system')).toBe('system');
    expect(pinMode('app')).toBe('app');
    expect(pinMode('')).toBe('app');
    expect(pinMode(null)).toBe('app');
  });
  it('PIN jest potrzebny tylko, gdy pyta o niego program', () => {
    expect(pinReady('app', '')).toBe(false);
    expect(pinReady('app', '1234')).toBe(true);
    expect(pinReady('system', '')).toBe(true);
  });
  it('napis czekania podaje numer dotknięcia', () => {
    expect(touchLabel(null)).toBe('Dotknij klucza...');
    expect(touchLabel({ step: 1, of: 1 })).toBe('Dotknij klucza...');
    expect(touchLabel({ step: 2, of: 3 })).toBe('Dotknij klucza (2 z 3)...');
  });
});
