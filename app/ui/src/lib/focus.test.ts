import { describe, expect, it } from 'vitest';
import { initialFocusIndex } from './focus';

describe('initialFocusIndex', () => {
  it('bierze pierwszego kandydata, gdy jest aktywny', () => {
    expect(initialFocusIndex([{ disabled: false }, { disabled: false }])).toBe(0);
  });
  it('pomija wyłączone elementy', () => {
    expect(initialFocusIndex([{ disabled: true }, { disabled: false }])).toBe(1);
  });
  it('zwraca null, gdy wszystko wyłączone (np. samotny przycisk główny z opóźnieniem) albo brak kandydatów', () => {
    expect(initialFocusIndex([{ disabled: true }])).toBeNull();
    expect(initialFocusIndex([])).toBeNull();
  });
});
