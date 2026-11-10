import { describe, expect, it } from 'vitest';
import { ACTIONS, binding, comboFromEvent, findConflict, matchAction, validCombo } from './shortcuts';
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
});

describe('bindings', () => {
  it('używa domyślnych i nadpisanych', () => {
    expect(binding(settings({}), 'quick_connect')).toBe('Ctrl+K');
    expect(binding(settings({ quick_connect: 'Ctrl+P' }), 'quick_connect')).toBe('Ctrl+P');
    expect(binding(settings({ quick_connect: '' }), 'quick_connect')).toBe('Ctrl+K');
  });
  it('rozpoznaje akcję i konflikty', () => {
    const s = settings({ lock: 'Ctrl+Alt+L' });
    expect(matchAction(s, ev('KeyL', { ctrlKey: true, altKey: true }))).toBe('lock');
    expect(matchAction(s, ev('KeyL', { ctrlKey: true, shiftKey: true }))).toBeNull();
    expect(findConflict(s, 'lock', 'Ctrl+K')).toBe('quick_connect');
    expect(findConflict(s, 'lock', 'Ctrl+Alt+L')).toBeNull();
  });
  it('domyślne skróty są unikalne i poprawne', () => {
    const seen = new Set(ACTIONS.map((a) => a.default));
    expect(seen.size).toBe(ACTIONS.length);
    for (const a of ACTIONS) expect(validCombo(a.default), a.id).toBe(true);
  });
});
