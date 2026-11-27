// Dodatkowe składniki przy otwieraniu pliku (klucz sprzętowy, kody TOTP): rozpoznawanie odpowiedzi
// backendu i drobne pomocniki do wyświetlania.

/** Co backend odpowiedział na próbę odblokowania albo podanie kodu. */
export type UnlockStep =
  /** Plik wymaga klucza sprzętowego; `message` to tryb PIN-u (`app` albo `system`). */
  | { kind: 'needs_key'; message: string }
  /** Klucz albo PIN nie pasował, można próbować dalej. */
  | { kind: 'bad_key'; message: string }
  /** Hasło było dobre, trzeba jeszcze podać kod. */
  | { kind: 'needs_code'; message: string }
  /** Kod był zły, można próbować dalej. */
  | { kind: 'bad_code'; message: string }
  /** Trzeba zacząć od hasła (za dużo prób albo minął czas). */
  | { kind: 'start_over'; message: string }
  /** Inny błąd, np. złe hasło. */
  | { kind: 'error'; message: string };

const PREFIXES: [string, UnlockStep['kind']][] = [
  ['NEEDS_KEY:', 'needs_key'],
  ['KEY_BAD:', 'bad_key'],
  ['KEY_EXPIRED:', 'start_over'],
  ['NEEDS_TOTP:', 'needs_code'],
  ['TOTP_BAD:', 'bad_code'],
  ['TOTP_EXPIRED:', 'start_over'],
];

/** Zamienia błąd komendy `unlock`, `unlock_key` albo `unlock_totp` na krok ekranu odblokowania. */
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

/** Kto pyta o PIN klucza: program (pole w oknie) albo system we własnym oknie. */
export type PinMode = 'app' | 'system';

/** Tryb PIN-u z odpowiedzi backendu; nieznana wartość oznacza pole w programie. */
export function pinMode(text: string | null | undefined): PinMode {
  return text === 'system' ? 'system' : 'app';
}

/** Czy można zacząć operację na kluczu: w trybie `app` potrzebny jest wpisany PIN. */
export function pinReady(mode: PinMode, pin: string): boolean {
  return mode === 'system' || pin.length > 0;
}

/** Napis na czas czekania na klucz, z numerem dotknięcia, gdy jest ich kilka. */
export function touchLabel(touch: { step: number; of: number } | null): string {
  if (!touch || touch.of <= 1) return 'Dotknij klucza...';
  return `Dotknij klucza (${touch.step} z ${touch.of})...`;
}
