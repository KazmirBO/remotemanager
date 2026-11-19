import { defaultSettings, type CursorShape, type FolderView, type HostView, type Settings, type TerminalFont } from './api';
import { inherited } from './tree';

export const FONT_STACKS: Record<TerminalFont, string> = {
  bundled: "'JetBrains Mono', ui-monospace, monospace",
  system: 'monospace',
};

export interface TerminalOpts {
  fontFamily: string;
  fontSize: number;
  cursorStyle: CursorShape;
  cursorBlink: boolean;
  scrollback: number;
  scheme: string;
  copyOnSelect: boolean;
  pasteRightClick: boolean;
}

/** Rozmiar i schemat: host -> katalogi (inherited) -> Settings; reszta z Settings; brak ustawień = defaultSettings(). */
export function terminalOptions(settings: Settings | undefined, host: HostView | undefined, folders: FolderView[]): TerminalOpts {
  const s = settings ?? defaultSettings();
  const fontSize =
    host?.fields.terminal_font_size ??
    (host ? (inherited(folders, host.folder, 'terminal_font_size')?.value as number | undefined) : undefined) ??
    s.terminal_font_size;
  const scheme =
    host?.fields.terminal_scheme ??
    (host ? (inherited(folders, host.folder, 'terminal_scheme')?.value as string | undefined) : undefined) ??
    s.terminal_scheme;
  return {
    fontFamily: FONT_STACKS[s.terminal_font] ?? FONT_STACKS.bundled,
    fontSize,
    cursorStyle: s.terminal_cursor,
    cursorBlink: s.terminal_cursor_blink,
    scrollback: s.terminal_scrollback,
    scheme,
    copyOnSelect: s.terminal_copy_on_select,
    pasteRightClick: s.terminal_paste_right_click,
  };
}
