import { describe, expect, it } from 'vitest';
import { MAX_POINTER_SIDE, validPointer } from './rdpPointer';

const shape = (w: number, h: number, patch: object = {}) => ({
  width: w, height: h, hot_x: 0, hot_y: 0, rgba: new Array(w * h * 4).fill(0), ...patch,
});

describe('validPointer', () => {
  it('przyjmuje kształt do 128 px', () => {
    expect(validPointer(shape(MAX_POINTER_SIDE, 1))).not.toBeNull();
    expect(validPointer(shape(1, MAX_POINTER_SIDE))).not.toBeNull();
  });
  it('odrzuca bok 0 i większy od 128', () => {
    expect(validPointer(shape(0, 4))).toBeNull();
    expect(validPointer(shape(MAX_POINTER_SIDE + 1, 1))).toBeNull();
  });
  it('odrzuca niezgodną długość rgba', () => {
    expect(validPointer(shape(2, 2, { rgba: [0, 0, 0] }))).toBeNull();
  });
  it('przycina punkt aktywny do bitmapy', () => {
    const p = validPointer(shape(4, 3, { hot_x: 99, hot_y: -5 }));
    expect(p?.hot_x).toBe(3);
    expect(p?.hot_y).toBe(0);
  });
});
