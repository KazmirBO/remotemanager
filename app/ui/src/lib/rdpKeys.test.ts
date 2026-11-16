import { describe, expect, it } from 'vitest';
import { createSerialQueue, grabActive, grabWanted, keyRoute, parseRelease } from './rdpKeys';
import { ACTIONS, binding, comboFromEvent, findConflict, hasScancode, matchAction, matchAppAction, validCombo } from './shortcuts';
import { validPointer } from './rdpPointer';

describe('parseRelease', () => {
  it('zamienia skrót domyślny na scancode i modyfikatory', () => {
    expect(parseRelease('Ctrl+Shift+F12')).toEqual({ scancode: 0x58, extended: false, ctrl: true, alt: false, shift: true, meta: false });
  });
  it('obsługuje klawisze rozszerzone, litery i znaki', () => {
    expect(parseRelease('Ctrl+PageDown')).toMatchObject({ scancode: 0x51, extended: true, ctrl: true });
    expect(parseRelease('Alt+Meta+K')).toMatchObject({ scancode: 0x25, extended: false, alt: true, meta: true, ctrl: false });
    expect(parseRelease('Ctrl+,')).toMatchObject({ scancode: 0x33, ctrl: true });
  });
  it('nieznany klawisz daje null', () => {
    expect(parseRelease('Ctrl+Nieznany')).toBeNull();
    expect(parseRelease('')).toBeNull();
  });
  it('każdy skrót domyślny da się zamienić', () => {
    for (const a of ACTIONS) expect(parseRelease(a.default), a.id).not.toBeNull();
  });
});

describe('grabWanted', () => {
  it('wynika z ustawienia', () => {
    expect(grabWanted('never', null, true)).toBe(false);
    expect(grabWanted('always', null, false)).toBe(true);
    expect(grabWanted('fullscreen', null, false)).toBe(false);
    expect(grabWanted('fullscreen', null, true)).toBe(true);
  });
  it('ręczny wybór ma pierwszeństwo', () => {
    expect(grabWanted('always', false, true)).toBe(false);
    expect(grabWanted('never', true, false)).toBe(true);
  });
});

describe('grabActive', () => {
  const ok = { connected: true, tabActive: true, focused: true, modal: false };
  it('wymaga wszystkich warunków', () => {
    expect(grabActive(true, ok)).toBe(true);
    expect(grabActive(false, ok)).toBe(false);
    for (const k of ['connected', 'tabActive', 'focused'] as const) expect(grabActive(true, { ...ok, [k]: false })).toBe(false);
    expect(grabActive(true, { ...ok, modal: true })).toBe(false);
  });
});

describe('keyRoute', () => {
  it('poza trybem skróty aplikacji zostają lokalne, a release_keys idzie do sesji', () => {
    expect(keyRoute('quick_connect', false)).toBe('app');
    expect(keyRoute('release_keys', false)).toBe('remote');
    expect(keyRoute(null, false)).toBe('remote');
  });
  it('w trybie wszystko poza release_keys idzie do sesji', () => {
    expect(keyRoute('quick_connect', true)).toBe('remote');
    expect(keyRoute('next_tab', true)).toBe('remote');
    expect(keyRoute(null, true)).toBe('remote');
    expect(keyRoute('release_keys', true)).toBe('release');
  });
});

describe('akcja release_keys', () => {
  const settings = (shortcuts: Record<string, string>) => ({
    theme: 'dark' as const, terminal_font_size: 13, terminal_scheme: 'domyslny', shortcuts, rdp_profile: 'fast' as const, rdp_keys: 'never' as const,
  });
  const ev = { ctrlKey: true, metaKey: false, altKey: false, shiftKey: true, code: 'F12' };
  it('ma skrót domyślny i jest edytowalna', () => {
    expect(matchAction(settings({}), ev)).toBe('release_keys');
    expect(matchAction(settings({ release_keys: 'Alt+F12' }), ev)).toBeNull();
    expect(matchAction(settings({ release_keys: 'Alt+F12' }), { ...ev, ctrlKey: false, shiftKey: false, altKey: true })).toBe('release_keys');
    expect(comboFromEvent(ev)).toBe('Ctrl+Shift+F12');
    expect(validCombo('Ctrl+Shift+F12')).toBe(true);
    expect(findConflict(settings({}), 'release_keys', 'Ctrl+Shift+K')).toBe('quick_connect');
    expect(findConflict(settings({}), 'quick_connect', 'Ctrl+Shift+F12')).toBe('release_keys');
  });
  it('globalna obsługa skrótów pomija akcję kontekstową, ale zwykłe skróty zostają', () => {
    expect(matchAppAction(settings({}), ev)).toBeNull();
    expect(matchAppAction(settings({}), { ...ev, code: 'KeyK' })).toBe('quick_connect');
  });
  it('wartość bez scancode zastępuje skrót domyślny, w tym w podpowiedzi i dopasowaniu', () => {
    const bad = settings({ release_keys: 'Ctrl+PrintScreen' });
    expect(hasScancode('Ctrl+PrintScreen')).toBe(false);
    expect(hasScancode('Ctrl+F13')).toBe(false);
    expect(hasScancode('Ctrl+Shift+F12')).toBe(true);
    expect(binding(bad, 'release_keys')).toBe('Ctrl+Shift+F12');
    expect(matchAction(bad, ev)).toBe('release_keys');
    expect(parseRelease(binding(bad, 'release_keys'))).not.toBeNull();
    expect(binding(settings({ release_keys: 'Alt+F11' }), 'release_keys')).toBe('Alt+F11');
    // Dla innych akcji wartość zapisana zostaje bez zmian.
    expect(binding(settings({ lock: 'Ctrl+F13' }), 'lock')).toBe('Ctrl+F13');
  });
});

describe('createSerialQueue', () => {
  it('wykonuje zadania po kolei, także gdy wcześniejsze trwa dłużej albo się nie udaje', async () => {
    const q = createSerialQueue();
    const log: string[] = [];
    const slow = q(async () => { await new Promise((r) => setTimeout(r, 20)); log.push('on'); return 1; });
    const failing = q(async () => { log.push('boom'); throw new Error('x'); });
    const last = q(async () => { log.push('off'); return 3; });
    expect(await slow).toBe(1);
    await expect(failing).rejects.toThrow();
    expect(await last).toBe(3);
    expect(log).toEqual(['on', 'boom', 'off']);
  });
});

describe('validPointer', () => {
  const ptr = (w: number, h: number, extra: Partial<{ hot_x: number; hot_y: number; len: number }> = {}) => ({
    width: w, height: h, hot_x: extra.hot_x ?? 0, hot_y: extra.hot_y ?? 0, rgba: new Array(extra.len ?? w * h * 4).fill(0),
  });
  it('przyjmuje poprawny kursor', () => {
    expect(validPointer(ptr(32, 32, { hot_x: 5, hot_y: 6 }))).toMatchObject({ width: 32, hot_x: 5, hot_y: 6 });
    expect(validPointer(ptr(128, 128))).not.toBeNull();
  });
  it('odrzuca zły rozmiar tablicy i boki spoza zakresu', () => {
    expect(validPointer(ptr(2, 2, { len: 15 }))).toBeNull();
    expect(validPointer(ptr(0, 4))).toBeNull();
    expect(validPointer(ptr(4, 0))).toBeNull();
    expect(validPointer(ptr(129, 1))).toBeNull();
    expect(validPointer(ptr(1.5, 2, { len: 12 }))).toBeNull();
  });
  it('przycina punkt aktywny do bitmapy', () => {
    expect(validPointer(ptr(4, 4, { hot_x: 99, hot_y: -3 }))).toMatchObject({ hot_x: 3, hot_y: 0 });
  });
});
