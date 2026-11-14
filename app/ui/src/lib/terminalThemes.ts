import type { ITheme } from '@xterm/xterm';

export const SCHEMES: Record<string, string> = {
  domyslny: 'Domyślny',
  szary: 'Skala szarości',
  kontrast: 'Wysoki kontrast',
};

// Paleta ANSI w skali szarości (DESIGN.md: wszystkie schematy bez barwy). Kolejność: black, red,
// green, yellow, blue, magenta, cyan, white, potem odmiany jasne. Odcienie różnią się jasnością,
// żeby kolory dało się rozróżnić bez barwy.
// Ciemne tło: jasne odcienie, "black" ciemny jak w zwykłych paletach.
const GRAY_DARK = [
  '#1a1a1a', '#8a8a8a', '#9a9a9a', '#b0b0b0', '#7a7a7a', '#a0a0a0', '#c0c0c0', '#d0d0d0',
  '#5a5a5a', '#a8a8a8', '#b8b8b8', '#d8d8d8', '#989898', '#c4c4c4', '#e0e0e0', '#f2f2f2',
];
// Jasne tło: wszystkie odcienie najwyżej #767676, czyli kontrast co najmniej 4.5:1 na bieli,
// także "white" i "brightWhite", które programy często używają jako zwykłego tekstu.
const GRAY_LIGHT = [
  '#000000', '#3c3c3c', '#505050', '#5e5e5e', '#2e2e2e', '#464646', '#585858', '#6a6a6a',
  '#727272', '#262626', '#404040', '#4c4c4c', '#1e1e1e', '#363636', '#525252', '#606060',
];

function ansi(palette: string[]): ITheme {
  const [black, red, green, yellow, blue, magenta, cyan, white, brightBlack, brightRed, brightGreen, brightYellow,
    brightBlue, brightMagenta, brightCyan, brightWhite] = palette;
  return {
    black, red, green, yellow, blue, magenta, cyan, white, brightBlack, brightRed, brightGreen, brightYellow,
    brightBlue, brightMagenta, brightCyan, brightWhite,
  };
}

/** Motyw xterm.js dla schematu; kolory tła i tekstu pochodzą z tokenów interfejsu. */
export function terminalTheme(scheme: string, css: CSSStyleDeclaration): ITheme {
  const c = (n: string) => css.getPropertyValue(n).trim();
  const light = document.documentElement.dataset.theme === 'light';
  const palette = ansi(light ? GRAY_LIGHT : GRAY_DARK);
  const base: ITheme = {
    background: c('--terminal'), foreground: c('--text'), cursor: c('--accent'), selectionBackground: c('--border-strong'),
    ...palette,
  };
  if (scheme === 'szary') {
    // Przygaszony: mniejszy kontrast tła i tekstu, do długiej pracy.
    return { ...base, background: light ? '#f2f2f2' : '#1c1c1c', foreground: light ? '#3a3a3a' : '#b4b4b4' };
  }
  if (scheme === 'kontrast') {
    return {
      ...base,
      background: light ? '#ffffff' : '#000000', foreground: light ? '#000000' : '#ffffff',
      cursor: light ? '#000000' : '#ffffff', selectionBackground: light ? '#bdbdbd' : '#555555',
      white: light ? '#000000' : '#ffffff', brightWhite: light ? '#000000' : '#ffffff',
    };
  }
  return base;
}
