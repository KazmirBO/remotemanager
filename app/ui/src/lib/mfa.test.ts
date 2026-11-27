import { describe, expect, it } from 'vitest';
import { groupSecret, looksLikeCode, unlockStep } from './mfa';

describe('unlockStep', () => {
  it('rozpoznaje odpowiedzi backendu po przedrostku', () => {
    expect(unlockStep('NEEDS_TOTP:Podaj kod z aplikacji uwierzytelniającej.'))
      .toEqual({ kind: 'needs_code', message: 'Podaj kod z aplikacji uwierzytelniającej.' });
    expect(unlockStep('TOTP_BAD:Nieprawidłowy kod.')).toEqual({ kind: 'bad_code', message: 'Nieprawidłowy kod.' });
    expect(unlockStep('TOTP_EXPIRED:Za dużo błędnych kodów. Podaj hasło główne ponownie.'))
      .toEqual({ kind: 'start_over', message: 'Za dużo błędnych kodów. Podaj hasło główne ponownie.' });
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
