/** Kolejność kart sesji: czyste funkcje dla przeciągania i przesuwania o jedno miejsce. */

/** Lista z elementem przeniesionym z pozycji `from` na pozycję `to` (liczoną po jego wyjęciu).
 * Indeksy spoza listy i `from === to` zwracają kopię bez zmian. */
export function moveItem<T>(list: readonly T[], from: number, to: number): T[] {
  const out = [...list];
  if (from < 0 || from >= out.length || to < 0 || to >= out.length || from === to) return out;
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item);
  return out;
}

/** Pozycja docelowa (dla `moveItem`) po upuszczeniu elementu `from` przed albo za elementem `target`. */
export function dropIndex(from: number, target: number, after: boolean): number {
  // Po wyjęciu przeciąganego elementu wszystko za nim przesuwa się o jedno miejsce w lewo.
  const shifted = target > from ? target - 1 : target;
  return shifted + (after && target !== from ? 1 : 0);
}
