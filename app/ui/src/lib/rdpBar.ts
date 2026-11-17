import type { Size } from './rdpSize';

/** Miejsce panelu sesji RDP: odległości (w pikselach) od bliższych krawędzi widoku. Zakotwiczenie
 * w bliższym rogu sprawia, że panel zostaje przy nim, gdy okno zmienia rozmiar. */
export interface BarPos { h: 'left' | 'right'; x: number; v: 'top' | 'bottom'; y: number }

/** Miejsce domyślne: prawy górny róg. */
export const DEFAULT_BAR: BarPos = { h: 'right', x: 8, v: 'top', y: 8 };

const KEY = 'mrm.rdpBar';
/** Górna granica zapisanej odległości; większa wartość to uszkodzony zapis, a nie położenie. */
const MAX_OFFSET = 100_000;

/** Lewy górny róg panelu ograniczony tak, żeby cały panel został w widoku. */
export function clampBar(left: number, top: number, bar: Size, box: Size): { left: number; top: number } {
  const side = (v: number, max: number) => Math.round(Math.min(Math.max(0, max), Math.max(0, v)));
  return { left: side(left, box.width - bar.width), top: side(top, box.height - bar.height) };
}

/** Zamienia położenie lewego górnego rogu na odległości od bliższych krawędzi widoku. */
export function anchorBar(left: number, top: number, bar: Size, box: Size): BarPos {
  const p = clampBar(left, top, bar, box);
  const right = Math.max(0, box.width - bar.width - p.left);
  const bottom = Math.max(0, box.height - bar.height - p.top);
  return {
    h: p.left <= right ? 'left' : 'right',
    x: Math.min(p.left, right),
    v: p.top <= bottom ? 'top' : 'bottom',
    y: Math.min(p.top, bottom),
  };
}

/** Styl CSS panelu. Odległość jest ograniczona rozmiarem widoku, więc panel nie wychodzi poza okno,
 * które zmalało od chwili zapisania położenia. */
export function barStyle(pos: BarPos, bar: Size): string {
  const side = (offset: number, size: number) => `max(0px, min(${offset}px, calc(100% - ${size}px)))`;
  return `${pos.h}: ${side(pos.x, bar.width)}; ${pos.v}: ${side(pos.y, bar.height)};`;
}

/** Odczytuje zapisane położenie; brak zapisu albo zapis niepoprawny dają miejsce domyślne. */
export function parseBarPos(raw: string | null): BarPos {
  try {
    const p = JSON.parse(raw ?? 'null') as Partial<BarPos> | null;
    const offset = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= MAX_OFFSET;
    if (p && (p.h === 'left' || p.h === 'right') && (p.v === 'top' || p.v === 'bottom') && offset(p.x) && offset(p.y)) {
      return { h: p.h, x: Math.round(p.x), v: p.v, y: Math.round(p.y) };
    }
  } catch { /* zapis nie jest poprawnym JSON-em */ }
  return { ...DEFAULT_BAR };
}

/** Położenie panelu zapamiętane na tej maszynie (pamięć lokalna widoku, jak rozwinięte katalogi). */
export function loadBarPos(): BarPos {
  try { return parseBarPos(localStorage.getItem(KEY)); } catch { return { ...DEFAULT_BAR }; }
}

export function saveBarPos(pos: BarPos) {
  try { localStorage.setItem(KEY, JSON.stringify(pos)); } catch { /* brak pamięci lokalnej */ }
}
