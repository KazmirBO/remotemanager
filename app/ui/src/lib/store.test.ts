import { beforeEach, describe, expect, it, vi } from 'vitest';

const userActivity = vi.fn(async () => {});
vi.mock('./api', () => ({ api: { lock: vi.fn(async () => {}), userActivity } }));

const { cancelPasswordPrompts, keyImportError, lockVault, needsKeyPassphrase, closeTab, openHost, requestCloseTabs, answerCloseTabs, reportActivity, setTabLive, onLocked, requestPassword, ui } = await import('./store.svelte');

function host(id: string) {
  return { id, name: id, address: id, protocol: 'ssh' as const, folder: null, favorite: false, notes: '', fields: {} as never };
}

beforeEach(() => {
  ui.tabs = [];
  ui.activeTab = null;
  cancelPasswordPrompts();
  ui.phase = 'unlocked';
  ui.closeConfirm = null;
  ui.quitConfirm = null;
  ui.doc = null;
  userActivity.mockClear();
});

describe('tytuły kart', () => {
  it('po zamknięciu środkowej karty nie powtarza tytułu', () => {
    for (let i = 0; i < 3; i++) openHost(host('a'));
    expect(ui.tabs.map((t) => t.title)).toEqual(['a', 'a (2)', 'a (3)']);
    closeTab(ui.tabs[1].id);
    openHost(host('a'));
    expect(ui.tabs.map((t) => t.title)).toEqual(['a', 'a (3)', 'a (2)']);
  });
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

function docWith(confirm: boolean) {
  return { settings: { confirm_close_tab: confirm } } as never;
}

describe('zamykanie kart z pytaniem', () => {
  it('bez opcji zamyka od razu', () => {
    openHost(host('a'));
    setTabLive(ui.tabs[0].id, true);
    ui.doc = docWith(false);
    requestCloseTabs([ui.tabs[0].id]);
    expect(ui.tabs.length).toBe(0);
    expect(ui.closeConfirm).toBeNull();
  });

  it('z opcją pyta tylko o połączone sesje', () => {
    ui.doc = docWith(true);
    openHost(host('a'));
    requestCloseTabs([ui.tabs[0].id]);
    expect(ui.tabs.length).toBe(0);
    openHost(host('b'));
    openHost(host('c'));
    setTabLive(ui.tabs[0].id, true);
    setTabLive(ui.tabs[1].id, true);
    const ids = ui.tabs.map((t) => t.id);
    requestCloseTabs(ids);
    expect(ui.closeConfirm?.live).toBe(2);
    expect(ui.tabs.length).toBe(2);
  });

  it('anulowanie nic nie zamyka, potwierdzenie zamyka', () => {
    ui.doc = docWith(true);
    openHost(host('a'));
    setTabLive(ui.tabs[0].id, true);
    requestCloseTabs([ui.tabs[0].id]);
    answerCloseTabs(false);
    expect(ui.tabs.length).toBe(1);
    expect(ui.closeConfirm).toBeNull();
    requestCloseTabs([ui.tabs[0].id]);
    answerCloseTabs(true);
    expect(ui.tabs.length).toBe(0);
  });

  it('blokada zeruje pytania', () => {
    ui.closeConfirm = { ids: ['x'], live: 1 };
    ui.quitConfirm = { sessions: 2 };
    onLocked();
    expect(ui.closeConfirm).toBeNull();
    expect(ui.quitConfirm).toBeNull();
  });
});

describe('aktywność użytkownika', () => {
  it('zgłasza najwyżej raz na 15 s i tylko przy odblokowanym pliku', () => {
    ui.phase = 'locked';
    reportActivity(1_000_000);
    expect(userActivity).not.toHaveBeenCalled();
    ui.phase = 'unlocked';
    reportActivity(1_000_000);
    reportActivity(1_010_000);
    expect(userActivity).toHaveBeenCalledTimes(1);
    reportActivity(1_015_000);
    expect(userActivity).toHaveBeenCalledTimes(2);
  });
});
