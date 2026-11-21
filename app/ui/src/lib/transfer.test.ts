import { describe, expect, it } from 'vitest';
import { emptyFields, type FolderView } from './api';
import { PARTS, defaultParts, exportPasswordError, exportText, folderChoices, importFormat, reportText, summaryText, type ImportReport, type Parts } from './transfer';

const all = (v: boolean): Parts => Object.fromEntries(PARTS.map((p) => [p.id, v])) as Parts;
const folder = (id: string, name: string, parent: string | null): FolderView => ({ id, name, parent, fields: emptyFields() });

describe('defaultParts', () => {
  it('odznacza hasła, klucze i ścieżki kluczy', () => {
    const d = defaultParts();
    expect(d.passwords).toBe(false);
    expect(d.ssh_keys).toBe(false);
    expect(d.key_paths).toBe(false);
    expect(d.usernames && d.options && d.login_command && d.notes && d.trusted_keys).toBe(true);
  });
  it('przy imporcie nie zaznacza kategorii, której plik nie ma', () => {
    const d = defaultParts({ ...all(false), usernames: true, passwords: true });
    expect(d).toEqual({ ...all(false), usernames: true });
  });
  it('przy imporcie polecenie po zalogowaniu i zaufane klucze trzeba zaznaczyć samemu', () => {
    const d = defaultParts(all(true));
    expect(d).toEqual({ ...all(false), usernames: true, options: true, notes: true });
  });
  it('obejmuje każdą kategorię dokładnie raz', () => {
    expect(new Set(PARTS.map((p) => p.id)).size).toBe(PARTS.length);
    expect(Object.keys(defaultParts()).sort()).toEqual(PARTS.map((p) => p.id).sort());
  });
});

describe('folderChoices', () => {
  it('daje pełne ścieżki posortowane po polsku', () => {
    const out = folderChoices([folder('b', 'Żuraw', null), folder('a', 'Firma', null), folder('c', 'Produkcja', 'a')]);
    expect(out.map((o) => o.label)).toEqual(['Firma', 'Firma / Produkcja', 'Żuraw']);
    expect(out[1].id).toBe('c');
  });
  it('nie zapętla się na cyklu katalogów', () => {
    const out = folderChoices([folder('a', 'A', 'b'), folder('b', 'B', 'a')]);
    expect(out.map((o) => o.label).sort()).toEqual(['A / B', 'B / A']);
  });
});

describe('importFormat', () => {
  it('rozpoznaje listę CSV po rozszerzeniu, bez względu na wielkość liter', () => {
    expect(importFormat('serwery.csv')).toBe('csv');
    expect(importFormat('SERWERY.CSV ')).toBe('csv');
    expect(importFormat('hosty.mrmx')).toBe('mrmx');
    expect(importFormat('lista.csv.mrmx')).toBe('mrmx');
    expect(importFormat('bez-rozszerzenia')).toBe('mrmx');
  });
});

describe('exportPasswordError', () => {
  it('wymaga 8 znaków i zgodności', () => {
    expect(exportPasswordError('krótkie', 'krótkie')).toMatch('co najmniej 8');
    expect(exportPasswordError('dostatecznie', 'inne-haslo')).toMatch('nie są takie same');
    expect(exportPasswordError('zażółć-1', 'zażółć-1')).toBeNull();
  });
});

describe('teksty', () => {
  it('eksport', () => {
    expect(exportText({ path: '/x', folders: 1, hosts: 2, trusted_keys: 0 })).toBe('Zapisano 2 hosty i 1 katalog.');
    expect(exportText({ path: '/x', folders: 5, hosts: 12, trusted_keys: 3 })).toBe('Zapisano 12 hostów i 5 katalogów, zaufane klucze: 3.');
  });
  it('podgląd importu', () => {
    const parts = all(false);
    expect(summaryText({ parts, folders_new: 3, folders_existing: 0, hosts_new: 12, hosts_existing: 0, trusted_new: 0 }))
      .toBe('W pliku: 12 hostów i 3 katalogi.');
    expect(summaryText({ parts: { ...parts, trusted_keys: true }, folders_new: 1, folders_existing: 2, hosts_new: 10, hosts_existing: 2, trusted_new: 5 }))
      .toBe('W pliku: 12 hostów (10 nowych, 2 już masz) i 3 katalogi (1 nowy, 2 już masz). Zaufane klucze do dodania: 5.');
  });
  it('wynik importu', () => {
    const none: ImportReport = { folders_added: 0, folders_updated: 0, hosts_added: 0, hosts_updated: 0, unchanged: 0, trusted_added: 0, trusted_conflicts: 0, jumps_dropped: 0 };
    expect(reportText(none)).toBe('Plik nie wniósł żadnych zmian.');
    expect(reportText({ ...none, hosts_added: 2, folders_added: 1 })).toBe('Dodano 2 hosty i 1 katalog.');
    expect(reportText({ ...none, hosts_updated: 1, unchanged: 4, trusted_added: 2, trusted_conflicts: 1, jumps_dropped: 1 }))
      .toBe('Zaktualizowano 1 host i 0 katalogów. Bez zmian: 4. Dodano zaufane klucze: 2. Pominięto zaufane klucze: 1 (masz dla tych hostów inny odcisk). Usunięto odwołania do bastionów, których nie ma na liście: 1.');
  });
});
