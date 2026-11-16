/** Największy bok kursora zdalnego (ten sam limit ma proces RDP). */
export const MAX_POINTER_SIDE = 128;

export interface PointerShape { width: number; height: number; hot_x: number; hot_y: number; rgba: number[] }

/** Sprawdza dane kursora z procesu RDP; `null` oznacza dane niepoprawne (wtedy kursor domyślny).
 * Punkt aktywny poza bitmapą jest przycinany do jej brzegu. */
export function validPointer(p: PointerShape): PointerShape | null {
  const side = (n: number) => Number.isInteger(n) && n > 0 && n <= MAX_POINTER_SIDE;
  if (!side(p.width) || !side(p.height)) return null;
  if (!Array.isArray(p.rgba) || p.rgba.length !== p.width * p.height * 4) return null;
  const clamp = (n: number, max: number) => (Number.isFinite(n) ? Math.max(0, Math.min(max - 1, Math.trunc(n))) : 0);
  return { ...p, hot_x: clamp(p.hot_x, p.width), hot_y: clamp(p.hot_y, p.height) };
}
