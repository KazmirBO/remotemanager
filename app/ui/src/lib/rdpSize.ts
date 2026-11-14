/** Rozmiar w pikselach. */
export interface Size { width: number; height: number }

/** Rozmiar pulpitu, o który prosimy serwer dla danego miejsca w oknie: wielokrotność 4 w zakresie
 * przyjmowanym przez proces RDP (200-8192). Obraz jest zawsze rysowany 1:1, więc to rozdzielczość
 * pulpitu, a nie skala obrazu, podąża za rozmiarem okna. */
export function desktopSize(boxWidth: number, boxHeight: number): Size {
  const side = (v: number) => Math.min(8192, Math.max(200, Math.floor(v / 4) * 4));
  return { width: side(boxWidth), height: side(boxHeight) };
}
