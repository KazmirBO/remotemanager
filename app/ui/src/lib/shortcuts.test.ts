import { describe, expect, it } from 'vitest';
import { ACTIONS, allowedWithModal, binding, comboFromEvent, findConflict, matchAction, validCombo } from './shortcuts';
import type { Settings } from './api';

const ev = (code: string, mods: Partial<Record<'ctrlKey' | 'metaKey' | 'altKey' | 'shiftKey', boolean>> = {}) => ({
  ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, code, ...mods,
});
const settings = (shortcuts: Record<string, string>): Settings => ({
  theme: 'dark', terminal_font_size: 13, terminal_scheme: 'domyslny', shortcuts,
});

describe('comboFromEvent', () => {
  it('buduje kanoniczną kombinację', () => {
    expect(comboFromEvent(ev('KeyK', { ctrlKey: true }))).toBe('Ctrl+K');
    expect(comboFromEvent(ev('KeyW', { ctrlKey: true, shiftKey: true }))).toBe('Ctrl+Shift+W');
    expect(comboFromEvent(ev('Comma', { ctrlKey: true }))).toBe('Ctrl+,');
    expect(comboFromEvent(ev('Digit1', { altKey: true }))).toBe('Alt+1');
    expect(comboFromEvent(ev('PageDown', { ctrlKey: true }))).toBe('Ctrl+PageDown');
  });
  it('sam modyfikator nie jest kombinacją', () => {
    expect(comboFromEvent(ev('ControlLeft', { ctrlKey: true }))).toBeNull();
    expect(comboFromEvent(ev('ShiftRight', { shiftKey: true }))).toBeNull();
  });
});

describe('validCombo', () => {
  it('wymaga modyfikatora innego niż Shift', () => {
    expect(validCombo('Ctrl+K')).toBe(true);
    expect(validCombo('Alt+Shift+X')).toBe(true);
    expect(validCombo('Shift+K')).toBe(false);
    expect(validCombo('K')).toBe(false);
    expect(validCombo('F5')).toBe(true);
  });
  it('odrzuca Ctrl+Alt, które na Windows jest AltGr', () => {
    expect(validCombo('Ctrl+Alt+L')).toBe(false);
    expect(validCombo('Ctrl+Alt+Shift+L')).toBe(false);
    expect(validCombo('Ctrl+Alt+Meta+L')).toBe(true);
    expect(validCombo('Alt+L')).toBe(true);
  });
});

describe('bindings', () => {
  it('używa domyślnych i nadpisanych', () => {
    expect(binding(settings({}), 'quick_connect')).toBe('Ctrl+Shift+K');
    expect(binding(settings({ quick_connect: 'Ctrl+P' }), 'quick_connect')).toBe('Ctrl+P');
    expect(binding(settings({ quick_connect: '' }), 'quick_connect')).toBe('Ctrl+Shift+K');
  });
  it('rozpoznaje akcję i konflikty', () => {
    const s = settings({ lock: 'Alt+Shift+L' });
    expect(matchAction(s, ev('KeyL', { altKey: true, shiftKey: true }))).toBe('lock');
    expect(matchAction(s, ev('KeyL', { ctrlKey: true, shiftKey: true }))).toBeNull();
    expect(findConflict(s, 'lock', 'Ctrl+Shift+K')).toBe('quick_connect');
    expect(findConflict(s, 'lock', 'Alt+Shift+L')).toBeNull();
  });
  it('AltGr nie uruchamia skrótu, nawet zapisanego wcześniej jako Ctrl+Alt', () => {
    const s = settings({ lock: 'Ctrl+Alt+L' });
    const altGr = { ...ev('KeyL', { ctrlKey: true, altKey: true }), getModifierState: (k: string) => k === 'AltGraph' };
    expect(matchAction(s, altGr)).toBeNull();
    expect(matchAction(s, ev('KeyL', { ctrlKey: true, altKey: true }))).toBe('lock');
  });
  it('przy otwartym oknie działa tylko blokada pliku', () => {
    expect(allowedWithModal('lock')).toBe(true);
    for (const a of ACTIONS.filter((x) => x.id !== 'lock')) expect(allowedWithModal(a.id), a.id).toBe(false);
  });
  it('domyślne skróty są unikalne i poprawne', () => {
    const seen = new Set(ACTIONS.map((a) => a.default));
    expect(seen.size).toBe(ACTIONS.length);
    for (const a of ACTIONS) expect(validCombo(a.default), a.id).toBe(true);
  });
  it('domyślne skróty nie zabierają klawiszy sterujących powłoki', () => {
    // Ctrl+litera trafia do zdalnej powłoki (np. Ctrl+K w bashu i nano), więc nie może być domyślnym skrótem.
    for (const a of ACTIONS) expect(a.default, a.id).not.toMatch(/^Ctrl\+[A-Z]$/);
    expect(matchAction(settings({}), ev('KeyK', { ctrlKey: true }))).toBeNull();
    expect(matchAction(settings({}), ev('KeyK', { ctrlKey: true, shiftKey: true }))).toBe('quick_connect');
  });
});
