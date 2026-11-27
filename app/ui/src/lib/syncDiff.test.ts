import { describe, expect, it } from 'vitest';
import { changeText, diffCount, diffGroups, diffIntro, diffIsEmpty, extraLines, type DiffItem, type DocDiff } from './syncDiff';

const item = (over: Partial<DiffItem>): DiffItem => ({
  id: 'x', name: 'db', path: 'Firma', address: '10.0.0.5', protocol: 'ssh', side: 'changed', changes: [], ...over,
});
const empty: DocDiff = { folders: [], hosts: [], defaults: [], trusted_local_only: 0, trusted_remote_only: 0, settings_differ: false, mfa_differ: false };

describe('changeText', () => {
  it('podaje obie wartości tam, gdzie nie są sekretem', () => {
    expect(changeText({ kind: 'name', local: 'db', remote: 'baza' })).toBe('nazwa: u Ciebie „db”, w folderze „baza”');
    expect(changeText({ kind: 'address', local: '10.0.0.5', remote: '10.0.0.50' })).toBe('adres: u Ciebie „10.0.0.5”, w folderze „10.0.0.50”');
    expect(changeText({ kind: 'protocol', local: 'ssh', remote: 'rdp' })).toBe('protokół: u Ciebie „SSH”, w folderze „RDP”');
    expect(changeText({ kind: 'location', local: 'Firma / Produkcja', remote: '' }))
      .toBe('położenie: u Ciebie „Firma / Produkcja”, w folderze „najwyższy poziom”');
  });
  it('dla pól z wartościami wrażliwymi podaje tylko nazwę', () => {
    expect(changeText({ kind: 'part', part: 'passwords' })).toBe('hasło');
    expect(changeText({ kind: 'part', part: 'ssh_keys' })).toBe('klucz prywatny SSH');
    expect(changeText({ kind: 'part', part: 'login_command' })).toBe('polecenie po zalogowaniu');
    expect(changeText({ kind: 'notes' })).toBe('notatki');
    expect(changeText({ kind: 'favorite' })).toBe('oznaczenie ulubionego');
  });
});

describe('diffGroups', () => {
  it('grupuje po stronie, katalogi przed hostami, bez pustych grup', () => {
    const d: DocDiff = {
      ...empty,
      folders: [item({ id: 'f', name: 'Test', side: 'remote_only', address: null, protocol: null })],
      hosts: [item({ id: 'a', side: 'remote_only' }), item({ id: 'b', side: 'changed' })],
    };
    const g = diffGroups(d);
    expect(g.map((x) => x.title)).toEqual(['Tylko w folderze', 'Różnią się']);
    expect(g[0].rows.map((r) => [r.type, r.id])).toEqual([['folder', 'f'], ['host', 'a']]);
    expect(g[1].rows.map((r) => r.id)).toEqual(['b']);
    expect(diffGroups(empty)).toEqual([]);
  });
});

describe('podsumowania', () => {
  it('pozostałe różnice', () => {
    expect(extraLines(empty)).toEqual([]);
    expect(extraLines({ ...empty, defaults: ['options', 'passwords'], trusted_local_only: 1, trusted_remote_only: 2, settings_differ: true })).toEqual([
      'Ustawienia domyślne drzewa: opcje połączenia, hasło.',
      'Zaufane klucze i certyfikaty: 1 tylko u Ciebie, 2 tylko w folderze.',
      'Ustawienia programu różnią się.',
    ]);
  });
  it('pusty wynik', () => {
    expect(diffIsEmpty(empty)).toBe(true);
    expect(diffIsEmpty({ ...empty, settings_differ: true })).toBe(false);
    expect(diffIsEmpty({ ...empty, mfa_differ: true })).toBe(false);
    expect(extraLines({ ...empty, mfa_differ: true })).toEqual(['Różni się wymóg dodatkowego składnika przy otwieraniu pliku.']);
    expect(diffIsEmpty({ ...empty, hosts: [item({})] })).toBe(false);
  });
  it('liczba pozycji z odmianą', () => {
    expect(diffCount({ ...empty, hosts: [item({})], folders: [] })).toBe('1 host i 0 katalogów');
    expect(diffCount({ ...empty, hosts: [item({}), item({}), item({})], folders: [item({}), item({})] })).toBe('3 hosty i 2 katalogi');
  });
  it('opis skutku zależy od stanu', () => {
    expect(diffIntro('zdalne_zmiany')).toMatch('pobierze wersję z folderu');
    expect(diffIntro('lokalne_zmiany')).toMatch('wyśle Twoją wersję');
    expect(diffIntro('konflikt')).toMatch('kopia konfliktu');
    expect(diffIntro('aktualny')).toBe('');
    expect(diffIntro(null)).toBe('');
  });
});
