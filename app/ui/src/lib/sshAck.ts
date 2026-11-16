/**
 * Licznik potwierdzeń wyjścia SSH (kontrola przepływu backendu). Widoczny dokument potwierdza bajty
 * dopiero po przetworzeniu przez terminal (`done`), co najmniej `threshold` naraz. Ukryty dokument
 * dławi liczniki czasu, więc wywołanie zwrotne xterma mogłoby przyjść z ogromnym opóźnieniem, a backend
 * wstrzymałby całe połączenie: bajty są wtedy potwierdzane od razu po odebraniu. Każdy bajt jest
 * liczony dokładnie raz, także gdy widoczność zmienia się w trakcie przetwarzania porcji.
 */
export interface Acker {
  /** Rejestruje odebraną porcję; zwraca `done` do wywołania po jej przetworzeniu. */
  receive(len: number): () => void;
  /** Dokument został ukryty: porcje czekające na przetworzenie liczą się jako potwierdzone. */
  hide(): void;
  /** Identyfikator sesji jest już znany, więc można wysyłać potwierdzenia (wcześniej bajty czekają). */
  ready(): void;
}

export function createAcker(send: (bytes: number) => void, hidden: () => boolean, threshold: number): Acker {
  let isReady = false;
  let counted = 0;
  const pending = new Set<{ len: number }>();
  const flush = () => {
    if (!isReady || counted === 0 || (!hidden() && counted < threshold)) return;
    const bytes = counted;
    counted = 0;
    send(bytes);
  };
  return {
    receive(len) {
      if (hidden()) {
        counted += len;
        flush();
        return () => {};
      }
      const chunk = { len };
      pending.add(chunk);
      return () => {
        if (!pending.delete(chunk)) return;
        counted += len;
        flush();
      };
    },
    hide() {
      for (const c of pending) counted += c.len;
      pending.clear();
      flush();
    },
    ready() {
      isReady = true;
      flush();
    },
  };
}
