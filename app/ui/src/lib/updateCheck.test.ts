import { describe, expect, it } from 'vitest';
import { checkForUpdate, compareVersions, newerVersion, parseVersion, type Release } from './updateCheck';

const rel = (tag_name: string, prerelease = false, draft = false): Release => ({ tag_name, prerelease, draft });
const cmp = (a: string, b: string) => Math.sign(compareVersions(parseVersion(a)!, parseVersion(b)!));

describe('parseVersion', () => {
  it('czyta numer z przyrostkiem i z literą v', () => {
    expect(parseVersion('0.1.0')).toEqual({ core: [0, 1, 0], pre: [] });
    expect(parseVersion('v0.1.1-rc1')).toEqual({ core: [0, 1, 1], pre: ['rc1'] });
    expect(parseVersion(' 1.2.3-rc.2+build5 ')).toEqual({ core: [1, 2, 3], pre: ['rc', '2'] });
  });
  it('odrzuca napisy, które nie są numerem wersji', () => {
    for (const bad of ['', 'latest', '1.2', 'v1', '1.2.3.4', '1.2.x']) expect(parseVersion(bad)).toBeNull();
  });
});

describe('compareVersions', () => {
  it('porównuje numer, a wydanie wstępne stawia przed końcowym', () => {
    expect(cmp('0.1.0', '0.1.1')).toBe(-1);
    expect(cmp('0.2.0', '0.1.9')).toBe(1);
    expect(cmp('1.0.0', '0.99.99')).toBe(1);
    expect(cmp('0.1.1-rc1', '0.1.1')).toBe(-1);
    expect(cmp('0.1.1-rc1', '0.1.0')).toBe(1);
    expect(cmp('0.1.1', '0.1.1')).toBe(0);
  });
  it('porównuje przyrostki wydań wstępnych', () => {
    expect(cmp('0.1.1-rc1', '0.1.1-rc2')).toBe(-1);
    expect(cmp('0.1.1-rc.2', '0.1.1-rc.10')).toBe(-1);
    expect(cmp('0.1.1-rc', '0.1.1-rc.1')).toBe(-1);
    expect(cmp('0.1.1-1', '0.1.1-rc')).toBe(-1);
    expect(cmp('0.1.1-beta', '0.1.1-rc1')).toBe(-1);
  });
});

describe('newerVersion', () => {
  const list = [rel('v0.1.1-rc2', true), rel('v0.1.1-rc1', true), rel('v0.1.0'), rel('v0.0.5', true)];
  it('użytkownikowi wydania zwykłego nie pokazuje wydań wstępnych', () => {
    expect(newerVersion('0.1.0', list)).toBeNull();
    expect(newerVersion('0.0.9', list)).toBe('0.1.0');
    expect(newerVersion('0.1.0', [...list, rel('v0.1.1')])).toBe('0.1.1');
  });
  it('użytkownikowi wydania wstępnego pokazuje też nowsze wstępne', () => {
    expect(newerVersion('0.1.1-rc1', list)).toBe('0.1.1-rc2');
    expect(newerVersion('0.1.1-rc2', list)).toBeNull();
    expect(newerVersion('0.1.1-rc2', [...list, rel('v0.1.1')])).toBe('0.1.1');
    expect(newerVersion('0.0.5-rc1', list)).toBe('0.1.1-rc2');
  });
  it('pomija szkice, obce tagi i błędne wpisy, a przy nieznanej własnej wersji milczy', () => {
    expect(newerVersion('0.1.0', [rel('v9.9.9', false, true), rel('nightly'), rel('v0.1.0')])).toBeNull();
    expect(newerVersion('0.1.0', [null as unknown as Release, { tag_name: 5 } as unknown as Release, rel('v0.2.0')])).toBe('0.2.0');
    // Wydanie oznaczone jako zwykłe, ale z przyrostkiem w numerze, też jest wstępne.
    expect(newerVersion('0.1.0', [rel('v0.2.0-rc1')])).toBeNull();
    expect(newerVersion('wersja-rozwojowa', list)).toBeNull();
  });
});

describe('checkForUpdate', () => {
  const answer = (body: unknown, ok = true) => (async () => ({ ok, json: async () => body })) as unknown as typeof fetch;
  it('zwraca nowszą wersję z odpowiedzi', async () => {
    expect(await checkForUpdate('0.1.0', answer([rel('v0.1.1'), rel('v0.1.0')]))).toBe('0.1.1');
    expect(await checkForUpdate('0.1.1', answer([rel('v0.1.1')]))).toBeNull();
  });
  it('przy błędzie sieci, złym statusie i dziwnej odpowiedzi zwraca null', async () => {
    expect(await checkForUpdate('0.1.0', (async () => { throw new Error('brak sieci'); }) as unknown as typeof fetch)).toBeNull();
    expect(await checkForUpdate('0.1.0', answer([rel('v0.2.0')], false))).toBeNull();
    expect(await checkForUpdate('0.1.0', answer({ message: 'rate limit' }))).toBeNull();
  });
  it('pyta właściwy adres i przerywa po limicie czasu', async () => {
    let asked = '';
    const slow = ((url: string, init: RequestInit) => {
      asked = url;
      return new Promise((_, reject) => init.signal!.addEventListener('abort', () => reject(new Error('przerwano'))));
    }) as unknown as typeof fetch;
    expect(await checkForUpdate('0.1.0', slow, 20)).toBeNull();
    expect(asked).toBe('https://api.github.com/repos/KazmirBO/remotemanager/releases?per_page=30');
  });
});
