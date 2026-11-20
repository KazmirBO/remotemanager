// Różnice między wersją lokalną a plikiem z folderu synchronizacji: typy z backendu i teksty.
import type { Id, Protocol, SyncStatus } from './api';
import { plural } from './tree';

export type DiffSide = 'local_only' | 'remote_only' | 'changed';
/** Kategoria pól, w której host albo katalog się różni; wartości backend nie ujawnia. */
export type FieldPart = 'usernames' | 'passwords' | 'ssh_keys' | 'key_paths' | 'options' | 'login_command';
export type DiffChange =
  | { kind: 'name'; local: string; remote: string }
  | { kind: 'address'; local: string; remote: string }
  | { kind: 'protocol'; local: Protocol; remote: Protocol }
  | { kind: 'location'; local: string; remote: string }
  | { kind: 'favorite' }
  | { kind: 'notes' }
  | { kind: 'part'; part: FieldPart };
export interface DiffItem {
  id: Id; name: string; path: string;
  /** Tylko hosty. */
  address: string | null; protocol: Protocol | null;
  side: DiffSide; changes: DiffChange[];
}
export interface DocDiff {
  folders: DiffItem[]; hosts: DiffItem[];
  defaults: FieldPart[];
  trusted_local_only: number; trusted_remote_only: number;
  settings_differ: boolean;
}
/** `readable: false` oznacza plik z innym hasłem głównym: nie da się go odczytać bez tego hasła. */
export interface SyncDiff { readable: boolean; diff: DocDiff | null }

const PART_LABELS: Record<FieldPart, string> = {
  usernames: 'nazwa użytkownika albo domena',
  passwords: 'hasło',
  ssh_keys: 'klucz prywatny SSH',
  key_paths: 'ścieżka pliku klucza',
  options: 'opcje połączenia',
  login_command: 'polecenie po zalogowaniu',
};

const place = (path: string) => path || 'najwyższy poziom';
const sides = (what: string, local: string, remote: string) => `${what}: u Ciebie „${local}”, w folderze „${remote}”`;

/** Jedna różnica słowami. Wartości mają tylko nazwa, adres, protokół i położenie. */
export function changeText(c: DiffChange): string {
  switch (c.kind) {
    case 'name': return sides('nazwa', c.local, c.remote);
    case 'address': return sides('adres', c.local, c.remote);
    case 'protocol': return sides('protokół', c.local.toUpperCase(), c.remote.toUpperCase());
    case 'location': return sides('położenie', place(c.local), place(c.remote));
    case 'favorite': return 'oznaczenie ulubionego';
    case 'notes': return 'notatki';
    case 'part': return PART_LABELS[c.part];
  }
}

export interface DiffRow extends DiffItem { type: 'folder' | 'host' }
export interface DiffGroup { side: DiffSide; title: string; rows: DiffRow[] }

const TITLES: Record<DiffSide, string> = {
  local_only: 'Tylko u Ciebie',
  remote_only: 'Tylko w folderze',
  changed: 'Różnią się',
};

/** Pozycje pogrupowane według strony; w grupie najpierw katalogi, potem hosty. Puste grupy odpadają. */
export function diffGroups(d: DocDiff): DiffGroup[] {
  const rows: DiffRow[] = [
    ...d.folders.map((f) => ({ ...f, type: 'folder' as const })),
    ...d.hosts.map((h) => ({ ...h, type: 'host' as const })),
  ];
  return (['local_only', 'remote_only', 'changed'] as const)
    .map((side) => ({ side, title: TITLES[side], rows: rows.filter((r) => r.side === side) }))
    .filter((g) => g.rows.length > 0);
}

/** Różnice poza hostami i katalogami: ustawienia domyślne drzewa, zaufane klucze, ustawienia programu. */
export function extraLines(d: DocDiff): string[] {
  const out: string[] = [];
  if (d.defaults.length) out.push(`Ustawienia domyślne drzewa: ${d.defaults.map((p) => PART_LABELS[p]).join(', ')}.`);
  if (d.trusted_local_only || d.trusted_remote_only) {
    out.push(`Zaufane klucze i certyfikaty: ${d.trusted_local_only} tylko u Ciebie, ${d.trusted_remote_only} tylko w folderze.`);
  }
  if (d.settings_differ) out.push('Ustawienia programu różnią się.');
  return out;
}

export function diffIsEmpty(d: DocDiff): boolean {
  return d.folders.length === 0 && d.hosts.length === 0 && extraLines(d).length === 0;
}

/** Liczba różniących się hostów i katalogów, do nagłówka listy. */
export function diffCount(d: DocDiff): string {
  const h = d.hosts.length, f = d.folders.length;
  return `${h} ${plural(h, 'host', 'hosty', 'hostów')} i ${f} ${plural(f, 'katalog', 'katalogi', 'katalogów')}`;
}

/** Co synchronizacja zrobi z pokazanymi różnicami, zależnie od stanu. */
export function diffIntro(status: SyncStatus | null): string {
  switch (status) {
    case 'zdalne_zmiany':
      return 'Synchronizacja pobierze wersję z folderu: pozycje „tylko u Ciebie” znikną, „tylko w folderze” dojdą, a różniące się przyjmą stan z folderu.';
    case 'lokalne_zmiany':
      return 'Synchronizacja wyśle Twoją wersję do folderu: pozycje „tylko w folderze” znikną stamtąd, „tylko u Ciebie” dojdą, a różniące się przyjmą Twój stan.';
    case 'konflikt':
      return 'Plik zmienił się po obu stronach. Zachowanie jednej wersji odrzuca różnice z drugiej; odrzucona wersja zostaje jako kopia konfliktu.';
    default:
      return '';
  }
}
