import { describe, expect, it } from 'vitest';
import { DEFAULT_BAR, anchorBar, barStyle, clampBar, parseBarPos } from './rdpBar';

const bar = { width: 120, height: 38 };
const box = { width: 1000, height: 600 };

describe('clampBar', () => {
  it('zostawia położenie mieszczące się w widoku', () => {
    expect(clampBar(300, 200, bar, box)).toEqual({ left: 300, top: 200 });
  });
  it('nie wypuszcza panelu poza żadną krawędź', () => {
    expect(clampBar(-50, -10, bar, box)).toEqual({ left: 0, top: 0 });
    expect(clampBar(5000, 5000, bar, box)).toEqual({ left: 880, top: 562 });
  });
  it('w widoku mniejszym od panelu trzyma lewy górny róg', () => {
    expect(clampBar(40, 40, bar, { width: 100, height: 20 })).toEqual({ left: 0, top: 0 });
  });
});

describe('anchorBar', () => {
  it('kotwiczy w bliższym rogu', () => {
    expect(anchorBar(10, 20, bar, box)).toEqual({ h: 'left', x: 10, v: 'top', y: 20 });
    expect(anchorBar(872, 8, bar, box)).toEqual({ h: 'right', x: 8, v: 'top', y: 8 });
    expect(anchorBar(30, 550, bar, box)).toEqual({ h: 'left', x: 30, v: 'bottom', y: 12 });
    expect(anchorBar(800, 500, bar, box)).toEqual({ h: 'right', x: 80, v: 'bottom', y: 62 });
  });
  it('położenie poza widokiem sprowadza do krawędzi', () => {
    expect(anchorBar(9999, -5, bar, box)).toEqual({ h: 'right', x: 0, v: 'top', y: 0 });
  });
  it('miejsce domyślne wraca jako miejsce domyślne', () => {
    expect(anchorBar(box.width - bar.width - 8, 8, bar, box)).toEqual(DEFAULT_BAR);
  });
});

describe('barStyle', () => {
  it('ogranicza odległość rozmiarem widoku', () => {
    expect(barStyle({ h: 'right', x: 8, v: 'bottom', y: 40 }, bar)).toBe(
      'right: max(0px, min(8px, calc(100% - 120px))); bottom: max(0px, min(40px, calc(100% - 38px)));',
    );
  });
});

describe('parseBarPos', () => {
  it('odczytuje poprawny zapis', () => {
    expect(parseBarPos('{"h":"left","x":12.4,"v":"bottom","y":3}')).toEqual({ h: 'left', x: 12, v: 'bottom', y: 3 });
  });
  it('brak zapisu i zapis niepoprawny dają miejsce domyślne', () => {
    for (const raw of [null, '', 'x', '[]', '{}', '{"h":"up","x":1,"v":"top","y":1}', '{"h":"left","x":-1,"v":"top","y":1}',
      '{"h":"left","x":"1","v":"top","y":1}', '{"h":"left","x":1e9,"v":"top","y":1}']) {
      expect(parseBarPos(raw)).toEqual(DEFAULT_BAR);
    }
  });
  it('nie zwraca wspólnego obiektu miejsca domyślnego', () => {
    expect(parseBarPos(null)).not.toBe(DEFAULT_BAR);
  });
});
