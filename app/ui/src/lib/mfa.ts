// Dodatkowy składnik przy otwieraniu pliku (kody TOTP): rozpoznawanie odpowiedzi backendu i drobne
// pomocniki do wyświetlania.

/** Co backend odpowiedział na próbę odblokowania albo podanie kodu. */
export type UnlockStep =
  /** Hasło było dobre, trzeba jeszcze podać kod. */
  | { kind: 'needs_code'; message: string }
  /** Kod był zły, można próbować dalej. */
  | { kind: 'bad_code'; message: string }
  /** Trzeba zacząć od hasła (za dużo prób albo minął czas). */
  | { kind: 'start_over'; message: string }
  /** Inny błąd, np. złe hasło. */
  | { kind: 'error'; message: string };

const PREFIXES: [string, UnlockStep['kind']][] = [
  ['NEEDS_TOTP:', 'needs_code'],
  ['TOTP_BAD:', 'bad_code'],
  ['TOTP_EXPIRED:', 'start_over'],
];

/** Zamienia błąd komendy `unlock` albo `unlock_totp` na krok ekranu odblokowania. */
export function unlockStep(err: unknown): UnlockStep {
  const text = String(err);
  for (const [prefix, kind] of PREFIXES) {
    if (text.startsWith(prefix)) return { kind, message: text.slice(prefix.length) };
  }
  return { kind: 'error', message: text };
}

/** Sekret base32 w grupach po cztery znaki, żeby dało się go przepisać bez pomyłki. */
export function groupSecret(secret: string): string {
  return secret.replace(/\s+/g, '').replace(/(.{4})(?=.)/g, '$1 ');
}

/** Czy tekst wygląda na kod TOTP (6 cyfr) albo kod zapasowy (10 znaków); spacje i łącznik się nie liczą. */
export function looksLikeCode(text: string): boolean {
  const t = text.replace(/[\s-]/g, '');
  return /^\d{6}$/.test(t) || /^[A-Za-z2-7]{10}$/.test(t);
}
