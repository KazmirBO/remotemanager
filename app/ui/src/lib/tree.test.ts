import { describe, expect, it } from 'vitest';
import { buildTree, descendantIds, inherited, inheritsPassword, matches, EDGE_SCROLL_MAX, edgeScrollSpeed } from './tree';
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
    // Poziom z pomijaną wartością jest przeskakiwany, dziedziczenie idzie wyżej.
    expect(inherited(f, 'b', 'port', 2200)).toEqual({ value: 2222, from: 'Firma' });
    expect(inherited(f, 'a', 'port', 2222)).toBeNull();
    expect(inherited(f, 'b', 'username', 'ktoś-inny')).toEqual({ value: 'admin', from: 'Firma' });
  });
  it('dziedziczy profil łącza RDP z najbliższego katalogu, który go ustawia', () => {
    const p = [folder('a', 'Firma', null, { rdp_profile: 'slow' }), folder('b', 'Sub', 'a'), folder('c', 'Biuro', 'b', { rdp_profile: 'fast' })];
    expect(inherited(p, 'b', 'rdp_profile')).toEqual({ value: 'slow', from: 'Firma' });
    expect(inherited(p, 'c', 'rdp_profile')).toEqual({ value: 'fast', from: 'Biuro' });
    // Żaden poziom nie ustawia profilu: wartość z Ustawień wybiera widok.
    expect(inherited([folder('x', 'X', null)], 'x', 'rdp_profile')).toBeNull();
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

describe('edgeScrollSpeed', () => {
  it('nie przewija w środku listy', () => {
    expect(edgeScrollSpeed(300, 100, 500)).toBe(0);
    expect(edgeScrollSpeed(141, 100, 500)).toBe(0);
    expect(edgeScrollSpeed(459, 100, 500)).toBe(0);
  });
  it('przewija w górę przy górnej krawędzi i w dół przy dolnej, szybciej bliżej krawędzi', () => {
    expect(edgeScrollSpeed(139, 100, 500)).toBeLessThan(0);
    expect(edgeScrollSpeed(461, 100, 500)).toBeGreaterThan(0);
    expect(Math.abs(edgeScrollSpeed(105, 100, 500))).toBeGreaterThan(Math.abs(edgeScrollSpeed(135, 100, 500)));
    expect(edgeScrollSpeed(100, 100, 500)).toBe(-EDGE_SCROLL_MAX);
    expect(edgeScrollSpeed(500, 100, 500)).toBe(EDGE_SCROLL_MAX);
  });
  it('wskaźnik poza listą przewija z największą prędkością', () => {
    expect(edgeScrollSpeed(20, 100, 500)).toBe(-EDGE_SCROLL_MAX);
    expect(edgeScrollSpeed(900, 100, 500)).toBe(EDGE_SCROLL_MAX);
  });
  it('w niskiej liście każda połowa przewija w swoją stronę', () => {
    expect(edgeScrollSpeed(110, 100, 140)).toBeLessThan(0);
    expect(edgeScrollSpeed(130, 100, 140)).toBeGreaterThan(0);
  });
});
