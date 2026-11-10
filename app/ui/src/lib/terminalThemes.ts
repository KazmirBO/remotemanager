import type { ITheme } from '@xterm/xterm';

export const SCHEMES: Record<string, string> = {
  domyslny: 'Domyślny',
  szary: 'Skala szarości',
  kontrast: 'Wysoki kontrast',
};

// Szesnaście odcieni szarości o rosnącej jasności, żeby kolory ANSI dało się rozróżnić bez barwy.
const GRAY_ANSI = [
  '#1a1a1a', '#4a4a4a', '#6a6a6a', '#8a8a8a', '#5a5a5a', '#7a7a7a', '#9a9a9a', '#c8c8c8',
  '#3a3a3a', '#707070', '#909090', '#b0b0b0', '#808080', '#a0a0a0', '#d0d0d0', '#f2f2f2',
];

/** Motyw xterm.js dla schematu; kolory tła i tekstu pochodzą z tokenów interfejsu. */
export function terminalTheme(scheme: string, css: CSSStyleDeclaration): ITheme {
  const c = (n: string) => css.getPropertyValue(n).trim();
  const base: ITheme = {
    background: c('--terminal'), foreground: c('--text'), cursor: c('--accent'), selectionBackground: c('--border-strong'),
  };
  if (scheme === 'szary') {
    const [black, red, green, yellow, blue, magenta, cyan, white, bBlack, bRed, bGreen, bYellow, bBlue, bMagenta, bCyan, bWhite] = GRAY_ANSI;
    return { ...base, black, red, green, yellow, blue, magenta, cyan, white, brightBlack: bBlack, brightRed: bRed,
      brightGreen: bGreen, brightYellow: bYellow, brightBlue: bBlue, brightMagenta: bMagenta, brightCyan: bCyan, brightWhite: bWhite };
  }
  if (scheme === 'kontrast') {
    const light = document.documentElement.dataset.theme === 'light';
    return { ...base, background: light ? '#ffffff' : '#000000', foreground: light ? '#000000' : '#ffffff',
      cursor: light ? '#000000' : '#ffffff', selectionBackground: light ? '#bdbdbd' : '#555555' };
  }
  return base;
}
