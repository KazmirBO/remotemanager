import { describe, expect, it } from 'vitest';
import { errorTab, visibleTabs } from './hostTabs';

describe('visibleTabs', () => {
  it('ukrywa zakładki według protokołu', () => {
    expect(visibleTabs('ssh')).toEqual(['general', 'login', 'connection', 'terminal']);
    expect(visibleTabs('rdp')).toEqual(['general', 'login', 'connection', 'redirects']);
    expect(visibleTabs(null)).toEqual(['general', 'login', 'connection', 'terminal', 'redirects']);
  });
});

describe('errorTab', () => {
  it('wskazuje zakładkę błędu', () => {
    expect(errorTab('Nazwa i adres hosta są wymagane.')).toBe('general');
    expect(errorTab('Nazwa katalogu nie może być pusta.')).toBe('general');
    expect(errorTab('przeniesienie utworzyłoby cykl katalogów')).toBe('general');
    expect(errorTab('KEY_PASSPHRASE: potrzebne hasło')).toBe('login');
    expect(errorTab('Ścieżka klucza jest niepoprawna.')).toBe('login');
    expect(errorTab('Zmiana psuje łańcuch bastionów: x')).toBe('connection');
    expect(errorTab('cykl w łańcuchu bastionów')).toBe('connection');
    expect(errorTab('bastion musi być hostem SSH')).toBe('connection');
    expect(errorTab('Typ terminala może mieć')).toBe('terminal');
    expect(errorTab('Rozmiar czcionki terminala musi być liczbą od 9 do 32.')).toBe('terminal');
    expect(errorTab('Polecenie po zalogowaniu może mieć')).toBe('terminal');
  });
  it('nazwa hosta w komunikacie nie zmienia zakładki', () => {
    expect(errorTab('Zmiana psuje łańcuch bastionów hosta Nazwa-jump: x.')).toBe('connection');
  });
  it('dla nieznanego błędu zwraca null', () => {
    expect(errorTab('Coś innego')).toBeNull();
  });
});
