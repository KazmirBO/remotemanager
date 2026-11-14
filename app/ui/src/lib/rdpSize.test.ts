import { describe, expect, it } from 'vitest';
import { desktopSize } from './rdpSize';

describe('desktopSize', () => {
  it('zaokrągla w dół do wielokrotności 4, żeby pulpit mieścił się w oknie bez skalowania', () => {
    expect(desktopSize(1283, 721)).toEqual({ width: 1280, height: 720 });
    expect(desktopSize(1280, 720)).toEqual({ width: 1280, height: 720 });
  });
  it('trzyma zakres przyjmowany przez proces RDP', () => {
    expect(desktopSize(50, 10)).toEqual({ width: 200, height: 200 });
    expect(desktopSize(20000, 9000)).toEqual({ width: 8192, height: 8192 });
  });
  it('wynik nigdy nie jest większy od okna, o ile okno ma co najmniej 200 px', () => {
    for (const [w, h] of [[201, 203], [999, 777], [1366, 768], [3841, 2161]]) {
      const d = desktopSize(w, h);
      expect(d.width).toBeLessThanOrEqual(w);
      expect(d.height).toBeLessThanOrEqual(h);
      expect(d.width % 4).toBe(0);
      expect(d.height % 4).toBe(0);
    }
  });
});
