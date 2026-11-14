/** Sprawdza rozmiar czcionki terminala: liczba całkowita z zakresu 9-32, inaczej komunikat błędu. */
export function fontSizeError(value: unknown): string | null {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 9 && value <= 32) return null;
  return 'Rozmiar czcionki terminala musi być liczbą całkowitą od 9 do 32.';
}

/** Sprawdza zmianę hasła głównego; gdy wszystkie pola są puste, zmiany nie ma i wynik to null. */
export function passwordChangeError(oldPw: string, newPw: string, newPw2: string): string | null {
  if (oldPw === '' && newPw === '' && newPw2 === '') return null;
  if (oldPw === '') return 'Podaj obecne hasło.';
  if ([...newPw].length < 8) return 'Nowe hasło musi mieć co najmniej 8 znaków.';
  if (newPw !== newPw2) return 'Nowe hasła nie są takie same.';
  return null;
}
