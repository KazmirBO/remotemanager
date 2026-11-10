import { describe, expect, it } from 'vitest';
import { SCANCODES, scancodeFor } from './scancodes';

describe('scancodeFor', () => {
  it('mapuje zwykłe i rozszerzone klawisze', () => {
    expect(scancodeFor('KeyA')).toEqual({ scancode: 0x1e, extended: false });
    expect(scancodeFor('ArrowUp')).toEqual({ scancode: 0x48, extended: true });
    expect(scancodeFor('NumpadEnter')).toEqual({ scancode: 0x1c, extended: true });
    expect(scancodeFor('Delete')).toEqual({ scancode: 0x53, extended: true });
  });
  it('nieznany klawisz zwraca null', () => {
    expect(scancodeFor('LaunchMail')).toBeNull();
  });
  it('każda para (kod, rozszerzenie) jest unikalna', () => {
    const seen = new Set<string>();
    for (const [name, [c, e]] of Object.entries(SCANCODES)) {
      const key = `${c}:${e}`;
      expect(seen.has(key), `${name} duplikuje ${key}`).toBe(false);
      seen.add(key);
    }
  });
});
