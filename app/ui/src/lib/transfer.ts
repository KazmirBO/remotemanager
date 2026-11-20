// Eksport i import hostów: kategorie danych, teksty podsumowań i kontrole formularza.
import type { FolderView, Id } from './api';
import { plural } from './tree';

export type PartId =
  | 'usernames' | 'passwords' | 'ssh_keys' | 'key_paths' | 'options' | 'login_command' | 'notes' | 'trusted_keys';
/** Kategorie danych; to samo co `model::transfer::Parts` w backendzie. */
export type Parts = Record<PartId, boolean>;

export interface ImportSummary {
  /** Kategorie obecne w pliku. */
  parts: Parts;
  folders_new: number; folders_existing: number;
  hosts_new: number; hosts_existing: number;
  trusted_new: number;
}
export interface ImportReport {
  folders_added: number; folders_updated: number;
  hosts_added: number; hosts_updated: number;
  unchanged: number;
  trusted_added: number; trusted_conflicts: number;
  jumps_dropped: number;
}
export interface ExportDone { path: string; folders: number; hosts: number; trusted_keys: number }

/** Największy plik importu (jak `MAX_IMPORT_FILE` w backendzie). */
export const MAX_IMPORT_FILE = 4 * 1024 * 1024;

/**
 * Kategorie w kolejności wyświetlania. `secret` to dane domyślnie odznaczone zawsze. `trust` to dane
 * domyślnie odznaczone przy imporcie: polecenie z pliku wykonałoby się na serwerze po połączeniu,
 * a zaufany klucz z pliku wyłącza pytanie o klucz hosta, więc bierze się je świadomie.
 */
export const PARTS: { id: PartId; label: string; secret?: boolean; trust?: boolean }[] = [
  { id: 'usernames', label: 'Nazwy użytkowników i domeny' },
  { id: 'passwords', label: 'Hasła', secret: true },
  { id: 'ssh_keys', label: 'Klucze prywatne SSH zapisane w pliku z hostami', secret: true },
  { id: 'key_paths', label: 'Ścieżki plików kluczy SSH (zależne od komputera)', secret: true },
  { id: 'options', label: 'Opcje połączenia (port, bastion, typ terminala, opcje RDP, wygląd terminala)' },
  { id: 'login_command', label: 'Polecenie po zalogowaniu', trust: true },
  { id: 'notes', label: 'Notatki' },
  { id: 'trusted_keys', label: 'Zaufane klucze hostów i certyfikaty', trust: true },
];

/**
 * Domyślny wybór. Eksport (bez argumentu): wszystko poza hasłami, kluczami i ścieżkami kluczy.
 * Import (`available` to kategorie obecne w pliku): to samo, ale bez polecenia po zalogowaniu
 * i zaufanych kluczy, i nigdy kategoria, której plik nie ma.
 */
export function defaultParts(available?: Parts): Parts {
  const out = {} as Parts;
  for (const p of PARTS) out[p.id] = !p.secret && (available ? available[p.id] && !p.trust : true);
  return out;
}

/** Katalogi do wyboru zakresu eksportu: pełna ścieżka nazw, posortowane. */
export function folderChoices(folders: FolderView[]): { id: Id; label: string }[] {
  const byId = new Map(folders.map((f) => [f.id, f]));
  const path = (f: FolderView): string => {
    const names: string[] = [];
    const seen = new Set<Id>();
    for (let cur: FolderView | undefined = f; cur && !seen.has(cur.id); cur = cur.parent ? byId.get(cur.parent) : undefined) {
      seen.add(cur.id);
      names.unshift(cur.name);
    }
    return names.join(' / ');
  };
  return folders.map((f) => ({ id: f.id, label: path(f) })).sort((a, b) => a.label.localeCompare(b.label, 'pl'));
}

/** Hasło pliku eksportu: co najmniej 8 znaków, dwa razy to samo. */
export function exportPasswordError(pw: string, pw2: string): string | null {
  if ([...pw].length < 8) return 'Hasło pliku eksportu musi mieć co najmniej 8 znaków.';
  if (pw !== pw2) return 'Hasła pliku eksportu nie są takie same.';
  return null;
}

const hosts = (n: number) => `${n} ${plural(n, 'host', 'hosty', 'hostów')}`;
const folders = (n: number) => `${n} ${plural(n, 'katalog', 'katalogi', 'katalogów')}`;
const fresh = (n: number) => `${n} ${plural(n, 'nowy', 'nowe', 'nowych')}`;

/** Jedno zdanie o tym, co zapisał eksport. */
export function exportText(d: ExportDone): string {
  const keys = d.trusted_keys ? `, zaufane klucze: ${d.trusted_keys}` : '';
  return `Zapisano ${hosts(d.hosts)} i ${folders(d.folders)}${keys}.`;
}

/** Podgląd importu: co jest w pliku i ile z tego już masz. */
export function summaryText(s: ImportSummary): string {
  const h = s.hosts_new + s.hosts_existing;
  const f = s.folders_new + s.folders_existing;
  const part = (total: string, n: number, existing: number) =>
    existing ? `${total} (${fresh(n)}, ${existing} już masz)` : total;
  let text = `W pliku: ${part(hosts(h), s.hosts_new, s.hosts_existing)} i ${part(folders(f), s.folders_new, s.folders_existing)}.`;
  if (s.parts.trusted_keys) text += ` Zaufane klucze do dodania: ${s.trusted_new}.`;
  return text;
}

/** Wynik importu w zdaniach; pomija to, czego nie było. */
export function reportText(r: ImportReport): string {
  const out: string[] = [];
  if (r.hosts_added || r.folders_added) out.push(`Dodano ${hosts(r.hosts_added)} i ${folders(r.folders_added)}.`);
  if (r.hosts_updated || r.folders_updated) out.push(`Zaktualizowano ${hosts(r.hosts_updated)} i ${folders(r.folders_updated)}.`);
  if (r.unchanged) out.push(`Bez zmian: ${r.unchanged}.`);
  if (r.trusted_added) out.push(`Dodano zaufane klucze: ${r.trusted_added}.`);
  if (r.trusted_conflicts) out.push(`Pominięto zaufane klucze: ${r.trusted_conflicts} (masz dla tych hostów inny odcisk).`);
  if (r.jumps_dropped) out.push(`Usunięto odwołania do bastionów, których nie ma na liście: ${r.jumps_dropped}.`);
  return out.length ? out.join(' ') : 'Plik nie wniósł żadnych zmian.';
}
