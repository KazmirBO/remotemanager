import type { RdpKeys, ReleaseCombo } from './api';
import { SCANCODES } from './scancodes';
import { CONTEXTUAL_ACTIONS, keyName } from './shortcuts';

/** Skrót w postaci "Ctrl+Shift+F12" na scancode i modyfikatory; `null`, gdy klawisz nie ma scancode. */
export function parseRelease(combo: string): ReleaseCombo | null {
  const parts = combo.split('+');
  const key = parts.pop();
  if (!key) return null;
  const code = Object.keys(SCANCODES).find((c) => keyName(c) === key);
  if (!code) return null;
  const [scancode, extended] = SCANCODES[code];
  return {
    scancode, extended,
    ctrl: parts.includes('Ctrl'), alt: parts.includes('Alt'), shift: parts.includes('Shift'), meta: parts.includes('Meta'),
  };
}

/**
 * Czy sesja ma tryb przechwytywania klawiszy, zanim sprawdzimy fokus i stan okna. Ręczny wybór
 * (`manual`: `null` oznacza brak wyboru) ma pierwszeństwo przed ustawieniem.
 */
export function grabWanted(setting: RdpKeys, manual: boolean | null, fullscreen: boolean): boolean {
  if (manual !== null) return manual;
  return setting === 'always' || (setting === 'fullscreen' && fullscreen);
}

/** Czy klawisze mają być teraz przechwycone: tryb chciany, sesja połączona, karta aktywna, kanwa z fokusem, bez okna modalnego. */
export function grabActive(
  wanted: boolean, s: { connected: boolean; tabActive: boolean; focused: boolean; modal: boolean },
): boolean {
  return wanted && s.connected && s.tabActive && s.focused && !s.modal;
}

/**
 * Co zrobić z klawiszem: `app` (skrót aplikacji zostaje lokalny), `remote` (idzie do zdalnej sesji)
 * albo `release` (zwolnienie trybu, klawisz nie idzie do sesji). W trybie przechwytywania tylko
 * `release_keys` jest odróżniany, a skróty aplikacji idą do zdalnej sesji. Poza trybem `release_keys`
 * nic nie znaczy, więc kombinacja idzie do sesji jak każdy inny klawisz.
 */
export function keyRoute(action: string | null, grabbing: boolean): 'app' | 'remote' | 'release' {
  if (grabbing) return action === 'release_keys' ? 'release' : 'remote';
  return action && !CONTEXTUAL_ACTIONS.has(action) ? 'app' : 'remote';
}

/** Kolejka wykonująca zadania po kolei: następne rusza po zakończeniu poprzedniego (także nieudanego). */
export function createSerialQueue(): <T>(task: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve();
  return (task) => {
    const run = tail.then(task, task);
    tail = run.catch(() => {});
    return run;
  };
}
