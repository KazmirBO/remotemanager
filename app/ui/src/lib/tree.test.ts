import { describe, expect, it } from 'vitest';
import { buildTree, descendantIds, inherited, inheritsPassword, matches } from './tree';
import { emptyFields, type FolderView, type HostView } from './api';

const folder = (id: string, name: string, parent: string | null, patch: Partial<ReturnType<typeof emptyFields>> = {}): FolderView => ({
  id, name, parent, fields: { ...emptyFields(), ...patch },
});
const host = (id: string, name: string, folderId: string | null): HostView => ({
  id, name, address: `${name}.example`, protocol: 'ssh', folder: folderId, favorite: false, notes: '', fields: emptyFields(),
});

describe('buildTree', () => {
  it('układa katalogi i hosty, sortując po polsku', () => {
    const folders = [folder('b', 'Łódź', null), folder('a', 'Zielona', null), folder('c', 'Sub', 'b')];
    const hosts = [host('1', 'zeta', 'b'), host('2', 'alfa', 'b'), host('3', 'root', null)];
    const { roots, rootHosts } = buildTree(folders, hosts);
    expect(roots.map((r) => r.folder.name)).toEqual(['Łódź', 'Zielona']);
    expect(roots[0].folders.map((f) => f.folder.name)).toEqual(['Sub']);
    expect(roots[0].hosts.map((h) => h.name)).toEqual(['alfa', 'zeta']);
    expect(rootHosts.map((h) => h.name)).toEqual(['root']);
  });

  it('elementy z nieistniejącym rodzicem trafiają do korzenia', () => {
    const { roots, rootHosts } = buildTree([folder('a', 'A', 'brak')], [host('1', 'h', 'brak')]);
    expect(roots).toHaveLength(1);
    expect(rootHosts).toHaveLength(1);
  });
});

describe('descendantIds', () => {
  it('zawiera katalog i potomków', () => {
    const f = [folder('a', 'A', null), folder('b', 'B', 'a'), folder('c', 'C', 'b'), folder('d', 'D', null)];
    expect([...descendantIds(f, 'a')].sort()).toEqual(['a', 'b', 'c']);
  });
});

describe('inherited', () => {
  const f = [folder('a', 'Firma', null, { username: 'admin', port: 2222 }), folder('b', 'Sub', 'a', { port: 2200 })];
  it('bierze najbliższą wartość w górę drzewa', () => {
    expect(inherited(f, 'b', 'port')).toEqual({ value: 2200, from: 'Sub' });
    expect(inherited(f, 'b', 'username')).toEqual({ value: 'admin', from: 'Firma' });
    expect(inherited(f, 'b', 'domain')).toBeNull();
    expect(inherited(f, null, 'port')).toBeNull();
  });
  it('nie zapętla się przy cyklu', () => {
    const cyc = [folder('a', 'A', 'b'), folder('b', 'B', 'a')];
    expect(inherited(cyc, 'a', 'port')).toBeNull();
  });
  it('wykrywa odziedziczone hasło', () => {
    const p = [folder('a', 'A', null, { has_password: true }), folder('b', 'B', 'a')];
    expect(inheritsPassword(p, 'b')).toBe('A');
    expect(inheritsPassword(p, null)).toBeNull();
  });
});

describe('matches', () => {
  it('szuka w nazwie, adresie i notatkach bez względu na wielkość liter', () => {
    const h = { ...host('1', 'Serwer', null), notes: 'Baza' };
    expect(matches(h, 'SERW')).toBe(true);
    expect(matches(h, 'example')).toBe(true);
    expect(matches(h, 'baza')).toBe(true);
    expect(matches(h, 'zzz')).toBe(false);
    expect(matches(h, '  ')).toBe(true);
  });
});
