import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./api', () => ({ api: { lock: vi.fn(async () => {}) } }));

const { cancelPasswordPrompts, keyImportError, lockVault, needsKeyPassphrase, openHost, requestPassword, ui } = await import('./store.svelte');

function host(id: string) {
  return { id, name: id, address: id, protocol: 'ssh' as const, folder: null, favorite: false, notes: '', fields: {} as never };
}

beforeEach(() => {
  ui.tabs = [];
  ui.activeTab = null;
  cancelPasswordPrompts();
  ui.phase = 'unlocked';
});

describe('blokada', () => {
  it('zamyka wszystkie karty, nie co drugą', async () => {
    for (const id of ['a', 'b', 'c', 'd']) openHost(host(id));
    expect(ui.tabs.length).toBe(4);
    await lockVault();
    expect(ui.tabs.length).toBe(0);
    expect(ui.activeTab).toBeNull();
    expect(ui.phase).toBe('locked');
  });

  it('anuluje otwarte monity o hasło', async () => {
    const p = requestPassword('A', 'powód', 'tab-a');
    await lockVault();
    await expect(p).resolves.toBeNull();
    expect(ui.passwordQueue.length).toBe(0);
  });
});

describe('monity o hasło', () => {
  it('drugi monit czeka w kolejce i żaden nie ginie', async () => {
    const a = requestPassword('A', 'r', 'tab-a');
    const b = requestPassword('B', 'r', 'tab-b');
    expect(ui.passwordQueue.map((p) => p.title)).toEqual(['A', 'B']);
    ui.passwordQueue[0].resolve('haslo-a');
    await expect(a).resolves.toBe('haslo-a');
    expect(ui.passwordQueue.map((p) => p.title)).toEqual(['B']);
    ui.passwordQueue[0].resolve('haslo-b');
    await expect(b).resolves.toBe('haslo-b');
  });

  it('zamknięcie karty anuluje tylko jej monit', async () => {
    const a = requestPassword('A', 'r', 'tab-a');
    const b = requestPassword('B', 'r', 'tab-b');
    cancelPasswordPrompts('tab-a');
    await expect(a).resolves.toBeNull();
    expect(ui.passwordQueue.map((p) => p.title)).toEqual(['B']);
    ui.passwordQueue[0].resolve(null);
    await expect(b).resolves.toBeNull();
  });
});

describe('błędy kluczy SSH', () => {
  it('needsKeyPassphrase wycina powód', () => {
    expect(needsKeyPassphrase('NEEDS_KEY_PASSPHRASE:Podaj hasło')).toBe('Podaj hasło');
    expect(needsKeyPassphrase('NEEDS_PASSWORD:x')).toBeNull();
    expect(needsKeyPassphrase('coś innego')).toBeNull();
  });
  it('keyImportError rozróżnia trzy prefiksy i ignoruje obce błędy', () => {
    expect(keyImportError('KEY_NEEDS_PASSPHRASE:Klucz jest zaszyfrowany.')).toEqual({ message: 'Klucz jest zaszyfrowany.', needsPassphrase: true });
    expect(keyImportError('KEY_BAD_PASSPHRASE:Zle.')).toEqual({ message: 'Zle.', needsPassphrase: true });
    expect(keyImportError('KEY_INVALID:Śmieci')).toEqual({ message: 'Śmieci', needsPassphrase: false });
    expect(keyImportError('Nazwa jest wymagana.')).toBeNull();
  });
});
