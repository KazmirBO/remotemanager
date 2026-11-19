<script lang="ts">
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import type { FolderView, HostView, Id, QuitRequest, TrustRequest } from './lib/api';
  import type { SettingsCategory } from './lib/settings/categories';
  import FolderDialog from './lib/FolderDialog.svelte';
  import HostDialog, { type Prefill } from './lib/HostDialog.svelte';
  import NotificationsDialog from './lib/NotificationsDialog.svelte';
  import PasswordPrompt from './lib/PasswordPrompt.svelte';
  import Icon from './lib/Icon.svelte';
  import Modal from './lib/Modal.svelte';
  import QuickConnect from './lib/QuickConnect.svelte';
  import SettingsDialog from './lib/SettingsDialog.svelte';
  import Sidebar from './lib/Sidebar.svelte';
  import RdpView from './lib/RdpView.svelte';
  import Terminal from './lib/Terminal.svelte';
  import TrustDialog from './lib/TrustDialog.svelte';
  import Unlock from './lib/Unlock.svelte';
  import { allowedWithModal, binding, matchAppAction, tabNumber } from './lib/shortcuts';
  import { api } from './lib/api';
  import { plural } from './lib/tree';
  import { answerCloseTabs, applyTheme, host as hostById, init, lockVault, modalOpen, notify, onLocked, openHost, reconnect, refreshSync, reportActivity, requestCloseTabs, ui } from './lib/store.svelte';

  type Dialog =
    | { kind: 'host'; host: HostView | null; folder: Id | null; prefill?: Prefill | null }
    | { kind: 'folder'; folder: FolderView | null; parent: Id | null }
    | { kind: 'settings'; category?: SettingsCategory }
    | { kind: 'notices' }
    | { kind: 'quick' }
    | { kind: 'link'; host: HostView; target: string };
  let dialog = $state<Dialog | null>(null);
  let trustQueue = $state<TrustRequest[]>([]);

  onMount(() => {
    init().catch((e) => notify(String(e), true));
    const unlisten = listen<TrustRequest>('trust-request', (e) => trustQueue.push(e.payload));
    // Blokada z zasobnika (albo z innego miejsca w backendzie): chowamy drzewo, karty i okna.
    const unlistenLock = listen('vault-locked', () => onLocked());
    // Pytanie o zaufanie wygasło po stronie backendu (120 s): okno znika, połączenie i tak padło.
    const unlistenExpired = listen<string>('trust-expired', (e) => {
      trustQueue = trustQueue.filter((r) => r.id !== e.payload);
    });
    // Kolejne uruchomienie z linkiem: odbieramy go od razu, a przy zablokowanym pliku czeka do odblokowania.
    const unlistenLink = listen('open-link', () => {
      if (ui.phase === 'unlocked') {
        void api.takePendingLink().then((url) => {
          if (url) void openLink(url);
        });
      } else {
        notify('Link czeka na odblokowanie pliku.');
      }
    });
    // Backend pyta o zakończenie programu, gdy są otwarte sesje i włączono `confirm_quit`.
    const unlistenQuit = listen<QuitRequest>('quit-requested', (e) => (ui.quitConfirm = e.payload));
    const media = matchMedia('(prefers-color-scheme: light)');
    const onScheme = () => applyTheme(ui.doc?.settings);
    media.addEventListener('change', onScheme);
    return () => {
      void unlisten.then((f) => f());
      void unlistenLock.then((f) => f());
      void unlistenExpired.then((f) => f());
      void unlistenLink.then((f) => f());
      void unlistenQuit.then((f) => f());
      media.removeEventListener('change', onScheme);
    };
  });

  async function openLink(url: string) {
    try {
      const l = await api.resolveLink(url);
      const existing = l.matching_host ? hostById(l.matching_host) : undefined;
      // Link nigdy nie łączy sam: pokazujemy pasujący host w drzewie i pytamy.
      if (existing) {
        ui.reveal = existing.id;
        dialog = { kind: 'link', host: existing, target: `${l.host}:${l.resolved_port}` };
        return;
      }
      dialog = {
        kind: 'host', host: null, folder: null,
        prefill: { protocol: l.protocol, address: l.host, port: l.port, username: l.username, domain: l.domain },
      };
    } catch (e) {
      notify(String(e), true);
    }
  }

  // Po blokadzie nie zostają otwarte okna ani prośby o zaufanie, które wróciłyby po odblokowaniu.
  $effect(() => {
    if (ui.phase !== 'unlocked') {
      dialog = null;
      trustQueue = [];
    }
  });

  // Link z wiersza poleceń czeka na odblokowanie pliku.
  $effect(() => {
    if (ui.phase === 'unlocked') {
      void api
        .takePendingLink()
        .then((url) => {
          if (url) void openLink(url);
        })
        .catch(() => {});
      const timer = setInterval(() => void refreshSync(), 30_000);
      return () => clearInterval(timer);
    }
  });

  function keydown(e: KeyboardEvent) {
    if (ui.phase !== 'unlocked') return;
    const action = matchAppAction(ui.doc?.settings, e);
    if (!action) return;
    // Przy otwartym oknie modalnym działa tylko blokada pliku.
    if (modalOpen() && !allowedWithModal(action)) return;
    e.preventDefault();
    const tabs = ui.tabs;
    const i = tabs.findIndex((t) => t.id === ui.activeTab);
    switch (action) {
      case 'quick_connect': dialog = { kind: 'quick' }; break;
      case 'close_tab': if (ui.activeTab) requestCloseTabs([ui.activeTab]); break;
      case 'new_host': dialog = { kind: 'host', host: null, folder: null }; break;
      case 'next_tab': if (tabs.length) ui.activeTab = tabs[(i + 1) % tabs.length].id; break;
      case 'prev_tab': if (tabs.length) ui.activeTab = tabs[(i - 1 + tabs.length) % tabs.length].id; break;
      case 'lock': void lockVault(); break;
      case 'settings': dialog = { kind: 'settings' }; break;
      case 'reconnect_tab': if (ui.activeTab) reconnect(ui.activeTab); break;
      case 'duplicate_tab': {
        const host = tabs[i] && hostById(tabs[i].hostId);
        if (host) openHost(host);
        break;
      }
      case 'focus_search': {
        const search = document.getElementById('host-search');
        if (search instanceof HTMLInputElement) {
          search.focus();
          search.select();
        }
        break;
      }
      default: {
        const n = tabNumber(action);
        if (n !== null && tabs[n - 1]) ui.activeTab = tabs[n - 1].id;
      }
    }
  }

  /** Menu przeglądarki (Wstecz, Odśwież, Drukuj) nie ma sensu w aplikacji, więc zostaje tylko tam,
   * gdzie daje kopiowanie i wklejanie: w polach tekstowych i w terminalu (xterm podstawia pod
   * wskaźnik własne pole tekstowe). Własne menu aplikacji (drzewo hostów) obsługują swoje elementy. */
  function contextmenu(e: MouseEvent) {
    const target = e.target;
    if (target instanceof Element && target.closest('input, textarea, [contenteditable]')) return;
    e.preventDefault();
  }

  // Menu karty pod prawym przyciskiem myszy.
  let tabMenu = $state<{ x: number; y: number; tabId: string } | null>(null);
  const menuTab = $derived(tabMenu ? ui.tabs.find((t) => t.id === tabMenu!.tabId) : undefined);
  const menuTabHost = $derived(menuTab ? hostById(menuTab.hostId) : undefined);

  function openTabMenu(e: MouseEvent, tabId: string) {
    e.preventDefault();
    tabMenu = { x: Math.min(e.clientX, innerWidth - 220), y: Math.min(e.clientY, innerHeight - 200), tabId };
  }

  /** Zamyka wszystkie karty poza wskazaną (`null` zamyka wszystkie). */
  function closeTabsExcept(keep: string | null) {
    requestCloseTabs(ui.tabs.filter((t) => t.id !== keep).map((t) => t.id));
  }

  // Pasek kart: karty zwężają się, a gdy i to nie wystarcza, pasek przewija się bez widocznego suwaka.
  let tabsEl = $state<HTMLDivElement>();

  /** Kółko myszy przewija pasek kart w poziomie, gdy karty się nie mieszczą. */
  function tabsWheel(e: WheelEvent) {
    if (!tabsEl || e.deltaY === 0 || tabsEl.scrollWidth <= tabsEl.clientWidth) return;
    e.preventDefault();
    tabsEl.scrollLeft += e.deltaY;
  }

  // Aktywna karta ma być widoczna także po przełączeniu skrótem albo otwarciu nowej sesji.
  $effect(() => {
    const id = ui.activeTab;
    void ui.tabs.length;
    if (!id) return;
    queueMicrotask(() => {
      const el = Array.from(tabsEl?.children ?? []).find((c) => (c as HTMLElement).dataset.tab === id);
      el?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    });
  });
</script>

<!-- Prawy przycisk gdziekolwiek zamyka otwarte menu karty (faza przechwytywania), zanim karta otworzy nowe. -->
<svelte:window
  onkeydown={(e) => {
    if (e.key === 'Escape') tabMenu = null;
    keydown(e);
  }}
  onclick={() => (tabMenu = null)}
  oncontextmenucapture={() => (tabMenu = null)}
  oncontextmenu={contextmenu}
  onkeydowncapture={() => reportActivity()}
  onpointerdowncapture={() => reportActivity()}
  onpointermovecapture={() => reportActivity()}
  onwheelcapture={() => reportActivity()}
/>

{#if ui.phase === 'loading'}
  <div class="center muted">Ładowanie...</div>
{:else if ui.phase !== 'unlocked'}
  <Unlock />
{:else}
  <div class="shell">
    <Sidebar
      onNewHost={(folder) => (dialog = { kind: 'host', host: null, folder })}
      onNewFolder={(parent) => (dialog = { kind: 'folder', folder: null, parent })}
      onEditHost={(host) => (dialog = { kind: 'host', host, folder: null })}
      onEditFolder={(folder) => (dialog = { kind: 'folder', folder, parent: null })}
      onSettings={() => (dialog = { kind: 'settings' })}
      onSync={() => (dialog = { kind: 'settings', category: 'sync' })}
      onLock={lockVault}
    />
    <main>
      <div class="tabs" role="tablist" aria-label="Sesje" bind:this={tabsEl} onwheel={tabsWheel}>
        {#each ui.tabs as t (t.id)}
          <div class="tab" class:active={ui.activeTab === t.id} role="presentation" data-tab={t.id} oncontextmenu={(e) => openTabMenu(e, t.id)}>
            <button role="tab" aria-selected={ui.activeTab === t.id} title={t.title} onclick={() => (ui.activeTab = t.id)}>
              <span class="badge {t.protocol}">{t.protocol.toUpperCase()}</span> <span class="tab-title">{t.title}</span>
            </button>
            <button class="icon-btn x" aria-label="Zamknij kartę {t.title}" onclick={() => requestCloseTabs([t.id])}><Icon name="close" size={14} /></button>
          </div>
        {/each}
        <!-- Przycisk zostaje przy prawej krawędzi także wtedy, gdy pasek kart jest przewinięty. -->
        <div class="add">
          <button class="icon-btn" aria-label="Szybkie łączenie" title="Szybkie łączenie" onclick={() => (dialog = { kind: 'quick' })}>
            <Icon name="plus" />
          </button>
        </div>
      </div>
      <div class="stage">
        {#each ui.tabs as t (t.id)}
          {#key t.generation}
            {#if t.protocol === 'rdp'}
              <RdpView tabId={t.id} hostId={t.hostId} active={ui.activeTab === t.id} />
            {:else}
              <Terminal tabId={t.id} hostId={t.hostId} active={ui.activeTab === t.id} />
            {/if}
          {/key}
        {/each}
        {#if ui.tabs.length === 0}
          <div class="welcome muted">
            <Icon name="terminal" size={28} />
            {#if binding(ui.doc?.settings, 'quick_connect')}
              <p>Kliknij dwukrotnie hosta w panelu albo naciśnij <kbd>{binding(ui.doc?.settings, 'quick_connect')}</kbd>, aby połączyć.</p>
            {:else}
              <p>Kliknij dwukrotnie hosta w panelu, aby połączyć.</p>
            {/if}
          </div>
        {/if}
      </div>
      <div class="status mono muted">
        <span>{ui.doc?.hosts.length ?? 0} {plural(ui.doc?.hosts.length ?? 0, 'host', 'hosty', 'hostów')}</span>
        <span>Otwartych sesji: {ui.tabs.length}</span>
        <button class="bell" aria-label="Powiadomienia ({ui.history.length})" title="Powiadomienia" onclick={() => (dialog = { kind: 'notices' })}>
          <Icon name="bell" size={14} />
          {#if ui.history.length}<span>{ui.history.length}</span>{/if}
        </button>
      </div>
    </main>
  </div>

  {#if dialog?.kind === 'host'}
    <HostDialog host={dialog.host} defaultFolder={dialog.folder} prefill={dialog.prefill ?? null} onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'folder'}
    <FolderDialog folder={dialog.folder} defaultParent={dialog.parent} onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'settings'}
    <SettingsDialog initial={dialog.category} onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'notices'}
    <NotificationsDialog onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'quick'}
    <QuickConnect onclose={() => (dialog = null)} onlink={openLink} />
  {:else if dialog?.kind === 'link'}
    {@const d = dialog}
    <Modal title="Połączyć z {d.host.name}?" onclose={() => (dialog = null)} width={460}>
      <p class="link-q">
        Link wskazuje zapisany host <b>{d.host.name}</b> ({d.host.protocol.toUpperCase()}, <span class="mono">{d.target}</span>).
        Połączenie użyje zapisanych ustawień tego hosta.
      </p>
      {#snippet footer()}
        <button class="btn" type="button" onclick={() => (dialog = null)}>Anuluj</button>
        <button class="btn primary" type="button" onclick={() => { openHost(d.host); dialog = null; }}>Połącz</button>
      {/snippet}
    </Modal>
  {/if}
  {#if ui.closeConfirm}
    {@const c = ui.closeConfirm}
    <Modal title={c.ids.length > 1 ? 'Zamknąć karty?' : 'Zamknąć kartę?'} onclose={() => answerCloseTabs(false)} width={460}>
      <p class="link-q">{c.live === 1 && c.ids.length === 1 ? 'Sesja w tej karcie jest połączona i zostanie rozłączona.' : `Połączone sesje (${c.live}) zostaną rozłączone.`}</p>
      {#snippet footer()}
        <button class="btn" type="button" onclick={() => answerCloseTabs(false)}>Anuluj</button>
        <button class="btn primary" type="button" onclick={() => answerCloseTabs(true)}>Zamknij</button>
      {/snippet}
    </Modal>
  {/if}
  {#if ui.quitConfirm}
    {@const q = ui.quitConfirm}
    <Modal title="Zakończyć program?" onclose={() => { ui.quitConfirm = null; void api.answerQuit(false); }} width={460}>
      <p class="link-q">Otwarte sesje ({q.sessions}) zostaną rozłączone.</p>
      {#snippet footer()}
        <button class="btn" type="button" onclick={() => { ui.quitConfirm = null; void api.answerQuit(false); }}>Anuluj</button>
        <button class="btn primary" type="button" onclick={() => { ui.quitConfirm = null; void api.answerQuit(true); }}>Zakończ</button>
      {/snippet}
    </Modal>
  {/if}
  {#if trustQueue.length}
    {@const first = trustQueue[0]}
    {#key first.id}
      <TrustDialog request={first} ondone={() => (trustQueue = trustQueue.filter((r) => r.id !== first.id))} />
    {/key}
  {/if}
{/if}

<PasswordPrompt />

{#if tabMenu && menuTab}
  {@const tab = menuTab}
  <div class="menu" role="menu" style="left:{tabMenu.x}px; top:{tabMenu.y}px">
    <button role="menuitem" onclick={() => reconnect(tab.id)}><Icon name="refresh" /> Połącz ponownie</button>
    <button role="menuitem" disabled={!menuTabHost} onclick={() => menuTabHost && openHost(menuTabHost)}><Icon name="copy" /> Duplikuj kartę</button>
    <hr />
    <button role="menuitem" onclick={() => requestCloseTabs([tab.id])}><Icon name="close" /> Zamknij kartę</button>
    <button role="menuitem" disabled={ui.tabs.length < 2} onclick={() => closeTabsExcept(tab.id)}><Icon name="close" /> Zamknij pozostałe</button>
    <button role="menuitem" onclick={() => closeTabsExcept(null)}><Icon name="close" /> Zamknij wszystkie</button>
  </div>
{/if}

{#if ui.notice}
  <!-- Błąd odróżnia ikona (kształt), nie sam kolor. -->
  <div class="toast" role={ui.noticeError ? 'alert' : 'status'}><Icon name={ui.noticeError ? 'alert' : 'info'} size={14} /> {ui.notice}</div>
{/if}

<style>
  .center { height: 100%; display: grid; place-items: center; }
  .link-q { margin: 0; overflow-wrap: anywhere; }
  .shell { display: flex; height: 100%; }
  main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  /* Suwak paska kart jest ukryty: widoczny zabierał wysokość paska i wywoływał drugi, pionowy.
     Pasek przewija się kółkiem myszy, a aktywna karta sama wchodzi w widok (`scroll-padding-right`
     zostawia miejsce na przyklejony przycisk szybkiego łączenia). */
  .tabs { height: 38px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; align-items: stretch; overflow-x: auto; overflow-y: hidden; scrollbar-width: none; scroll-padding-right: 44px; flex-shrink: 0; }
  .tabs::-webkit-scrollbar { display: none; }
  /* Karty zwężają się do stałej szerokości minimalnej (odznaka, kilka znaków nazwy, przycisk zamknięcia);
     nazwa jest ucinana wielokropkiem, a pełną pokazuje podpowiedź. */
  .tab { display: flex; align-items: center; flex: 0 1 auto; min-width: 9.5rem; border-right: 1px solid var(--border); padding-right: 4px; }
  .tab > button[role='tab'] { background: transparent; border: none; height: 100%; padding: 0 8px 0 12px; display: flex; align-items: center; gap: 8px; flex: 1 1 auto; min-width: 0; max-width: 220px; white-space: nowrap; }
  .tab > button[role='tab'] > .badge { flex-shrink: 0; }
  .tab-title { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
  .tab > .x { flex-shrink: 0; }
  .tab.active { background: var(--terminal); box-shadow: inset 0 -2px 0 var(--accent); }
  .tab:not(.active):hover { background: var(--hover); }
  .add { position: sticky; right: 0; flex-shrink: 0; display: flex; align-items: center; padding: 0 6px; background: var(--panel); }
  .stage { flex: 1; position: relative; background: var(--terminal); min-height: 0; }
  .welcome { position: absolute; inset: 0; display: flex; flex-direction: column; gap: 8px; align-items: center; justify-content: center; text-align: center; padding: 16px; }
  .welcome p { margin: 0; }
  kbd { font-family: var(--font-mono); font-size: 12px; border: 1px solid var(--border-strong); border-radius: var(--radius-badge); padding: 1px 5px; background: var(--surface); }
  .status { height: 26px; background: var(--panel); border-top: 1px solid var(--border); display: flex; gap: 16px; align-items: center; padding: 0 12px; flex-shrink: 0; }
  .bell { margin-left: auto; background: none; border: none; display: inline-flex; gap: 4px; align-items: center; color: var(--text-muted); padding: 0 4px; height: 100%; }
  .bell:hover { color: var(--text); }
  .toast { position: fixed; bottom: 40px; left: 50%; transform: translateX(-50%); z-index: 80; background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--radius-control); padding: 10px 14px; box-shadow: var(--shadow-float); display: flex; gap: 8px; align-items: center; max-width: 90vw; }
</style>
