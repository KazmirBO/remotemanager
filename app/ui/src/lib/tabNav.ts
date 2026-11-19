/**
 * Docelowy indeks zakładki po naciśnięciu klawisza (wzorzec ARIA tabs) albo `null`, gdy klawisz
 * nie służy do nawigacji. Strzałki zawijają się na końcach listy.
 */
export function tabKeyTarget(
  key: string, index: number, count: number, orientation: 'horizontal' | 'vertical',
): number | null {
  if (count <= 0) return null;
  const prev = orientation === 'horizontal' ? 'ArrowLeft' : 'ArrowUp';
  const next = orientation === 'horizontal' ? 'ArrowRight' : 'ArrowDown';
  switch (key) {
    case prev: return (index - 1 + count) % count;
    case next: return (index + 1) % count;
    case 'Home': return 0;
    case 'End': return count - 1;
    default: return null;
  }
}
