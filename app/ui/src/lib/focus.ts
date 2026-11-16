// Wybór elementu początkowego fokusu w oknie modalnym, wydzielony z komponentu, żeby dał się
// sprawdzić bez DOM. Kandydaci są w kolejności dokumentu; wyłączone kontrolki nie przyjmują fokusu
// (`focus()` jest wtedy bez skutku), więc je pomijamy. Brak wyniku oznacza: fokus na samo okno.
export interface FocusCandidate {
  disabled: boolean;
}

export function initialFocusIndex(candidates: readonly FocusCandidate[]): number | null {
  const i = candidates.findIndex((c) => !c.disabled);
  return i < 0 ? null : i;
}
