import { describe, expect, it } from 'vitest';
import { defaultSettings, emptyFields, type FolderView, type HostView } from './api';
import { FONT_STACKS, terminalOptions } from './terminalOptions';

const folder = (id: string, parent: string | null, patch: Partial<ReturnType<typeof emptyFields>> = {}): FolderView => ({
  id, name: id, parent, fields: { ...emptyFields(), ...patch },
});
const host = (folderId: string | null, patch: Partial<ReturnType<typeof emptyFields>> = {}): HostView => ({
  id: 'h', name: 'h', address: 'h', protocol: 'ssh', folder: folderId, favorite: false, notes: '', fields: { ...emptyFields(), ...patch },
});

describe('terminalOptions', () => {
  it('bez ustawień daje wartości domyślne', () => {
    const o = terminalOptions(undefined, undefined, []);
    expect(o.fontSize).toBe(13);
    expect(o.scrollback).toBe(5000);
    expect(o.cursorStyle).toBe('block');
    expect(o.cursorBlink).toBe(true);
    expect(o.fontFamily).toBe(FONT_STACKS.bundled);
    expect(o.scheme).toBe('domyslny');
  });

  it('rozmiar: host przed katalogiem przed ustawieniami', () => {
    const s = { ...defaultSettings(), terminal_font_size: 14 };
    const folders = [folder('a', null, { terminal_font_size: 18 }), folder('b', 'a')];
    expect(terminalOptions(s, host('b'), folders).fontSize).toBe(18);
    expect(terminalOptions(s, host('b', { terminal_font_size: 20 }), folders).fontSize).toBe(20);
    expect(terminalOptions(s, host(null), folders).fontSize).toBe(14);
  });

  it('schemat dziedziczy z katalogu, reszta z ustawień', () => {
    const s = { ...defaultSettings(), terminal_font: 'system' as const, terminal_cursor: 'bar' as const, terminal_cursor_blink: false, terminal_scrollback: 0 };
    const o = terminalOptions(s, host('a'), [folder('a', null, { terminal_scheme: 'solarized' })]);
    expect(o.scheme).toBe('solarized');
    expect(o.fontFamily).toBe('monospace');
    expect(o.cursorStyle).toBe('bar');
    expect(o.cursorBlink).toBe(false);
    expect(o.scrollback).toBe(0);
  });
});
