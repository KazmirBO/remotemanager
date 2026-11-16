<script lang="ts">
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import type { FolderView, HostView, Id, TrustRequest } from './lib/api';
  import AboutDialog from './lib/AboutDialog.svelte';
  import BackupsDialog from './lib/BackupsDialog.svelte';
  import DiagnosticsDialog from './lib/DiagnosticsDialog.svelte';
  import FolderDialog from './lib/FolderDialog.svelte';
  import HostDialog, { type Prefill } from './lib/HostDialog.svelte';
  import NotificationsDialog from './lib/NotificationsDialog.svelte';
  import PasswordPrompt from './lib/PasswordPrompt.svelte';
  import Icon from './lib/Icon.svelte';
  import Modal from './lib/Modal.svelte';
  import QuickConnect from './lib/QuickConnect.svelte';
  import SettingsDialog from './lib/SettingsDialog.svelte';
  import ShortcutsDialog from './lib/ShortcutsDialog.svelte';
  import SyncDialog from './lib/SyncDialog.svelte';
  import Sidebar from './lib/Sidebar.svelte';
  import RdpView from './lib/RdpView.svelte';
  import Terminal from './lib/Terminal.svelte';
  import TrustDialog from './lib/TrustDialog.svelte';
  import Unlock from './lib/Unlock.svelte';
  import { allowedWithModal, binding, matchAppAction } from './lib/shortcuts';
  import { api } from './lib/api';
  import { applyTheme, closeTab, host as hostById, init, lockVault, modalOpen, notify, onLocked, openHost, refreshSync, ui } from './lib/store.svelte';

  type Dialog =
    | { kind: 'host'; host: HostView | null; folder: Id | null; prefill?: Prefill | null }
    | { kind: 'folder'; folder: FolderView | null; parent: Id | null }
    | { kind: 'settings' }
    | { kind: 'sync' }
    | { kind: 'backups' }
    | { kind: 'shortcuts' }
    | { kind: 'diagnostics' }
    | { kind: 'about' }
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
    const media = matchMedia('(prefers-color-scheme: light)');
    const onScheme = () => applyTheme(ui.doc?.settings);
    media.addEventListener('change', onScheme);
    return () => {
      void unlisten.then((f) => f());
      void unlistenLock.then((f) => f());
      void unlistenExpired.then((f) => f());
      void unlistenLink.then((f) => f());
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
    // Okno przechwytujące skrót (ustawianie skrótów) obsługuje klawisze samo.
    if (dialog?.kind === 'shortcuts') return;
    const action = matchAppAction(ui.doc?.settings, e);
    if (!action) return;
    // Przy otwartym oknie modalnym działa tylko blokada pliku.
    if (modalOpen() && !allowedWithModal(action)) return;
    e.preventDefault();
    const tabs = ui.tabs;
    const i = tabs.findIndex((t) => t.id === ui.activeTab);
    switch (action) {
      case 'quick_connect': dialog = { kind: 'quick' }; break;
      case 'close_tab': if (ui.activeTab) closeTab(ui.activeTab); break;
      case 'new_host': dialog = { kind: 'host', host: null, folder: null }; break;
      case 'next_tab': if (tabs.length) ui.activeTab = tabs[(i + 1) % tabs.length].id; break;
      case 'prev_tab': if (tabs.length) ui.activeTab = tabs[(i - 1 + tabs.length) % tabs.length].id; break;
      case 'lock': void lockVault(); break;
      case 'settings': dialog = { kind: 'settings' }; break;
    }
  }
</script>

<svelte:window onkeydown={keydown} />

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
      onSync={() => (dialog = { kind: 'sync' })}
      onLock={lockVault}
    />
    <main>
      <div class="tabs" role="tablist" aria-label="Sesje">
        {#each ui.tabs as t (t.id)}
          <div class="tab" class:active={ui.activeTab === t.id} role="presentation">
            <button role="tab" aria-selected={ui.activeTab === t.id} onclick={() => (ui.activeTab = t.id)}>
              <span class="badge {t.protocol}">{t.protocol.toUpperCase()}</span> {t.title}
            </button>
            <button class="icon-btn x" aria-label="Zamknij kartę {t.title}" onclick={() => closeTab(t.id)}><Icon name="close" size={14} /></button>
          </div>
        {/each}
        <button class="icon-btn add" aria-label="Szybkie łączenie" title="Szybkie łączenie" onclick={() => (dialog = { kind: 'quick' })}>
          <Icon name="plus" />
        </button>
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
            <p>Kliknij dwukrotnie hosta w panelu albo naciśnij <kbd>{binding(ui.doc?.settings, 'quick_connect')}</kbd>, aby połączyć.</p>
          </div>
        {/if}
      </div>
      <div class="status mono muted">
        <span>{ui.doc?.hosts.length ?? 0} hostów</span>
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
    <SettingsDialog onclose={() => (dialog = null)} onopen={(tool) => (dialog = { kind: tool })} />
  {:else if dialog?.kind === 'sync'}
    <SyncDialog onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'backups'}
    <BackupsDialog onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'shortcuts'}
    <ShortcutsDialog onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'diagnostics'}
    <DiagnosticsDialog onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'notices'}
    <NotificationsDialog onclose={() => (dialog = null)} />
  {:else if dialog?.kind === 'about'}
    <AboutDialog onclose={() => (dialog = null)} />
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
  {#if trustQueue.length}
    {#key trustQueue[0].id}
      <TrustDialog request={trustQueue[0]} ondone={() => trustQueue.shift()} />
    {/key}
  {/if}
{/if}

<PasswordPrompt />

{#if ui.notice}
  <!-- Błąd odróżnia ikona (kształt), nie sam kolor. -->
  <div class="toast" role={ui.noticeError ? 'alert' : 'status'}><Icon name={ui.noticeError ? 'alert' : 'info'} size={14} /> {ui.notice}</div>
{/if}

<style>
  .center { height: 100%; display: grid; place-items: center; }
  .link-q { margin: 0; overflow-wrap: anywhere; }
  .shell { display: flex; height: 100%; }
  main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .tabs { height: 38px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; align-items: stretch; overflow-x: auto; flex-shrink: 0; }
  .tab { display: flex; align-items: center; border-right: 1px solid var(--border); padding-right: 4px; }
  .tab > button[role='tab'] { background: transparent; border: none; height: 100%; padding: 0 8px 0 12px; display: flex; align-items: center; gap: 8px; max-width: 220px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .tab.active { background: var(--terminal); box-shadow: inset 0 -2px 0 var(--accent); }
  .tab:not(.active):hover { background: var(--hover); }
  .add { align-self: center; margin: 0 6px; }
  .stage { flex: 1; position: relative; background: var(--terminal); min-height: 0; }
  .welcome { position: absolute; inset: 0; display: flex; flex-direction: column; gap: 8px; align-items: center; justify-content: center; text-align: center; padding: 16px; }
  .welcome p { margin: 0; }
  kbd { font-family: var(--font-mono); font-size: 12px; border: 1px solid var(--border-strong); border-radius: var(--radius-badge); padding: 1px 5px; background: var(--surface); }
  .status { height: 26px; background: var(--panel); border-top: 1px solid var(--border); display: flex; gap: 16px; align-items: center; padding: 0 12px; flex-shrink: 0; }
  .bell { margin-left: auto; background: none; border: none; display: inline-flex; gap: 4px; align-items: center; color: var(--text-muted); padding: 0 4px; height: 100%; }
  .bell:hover { color: var(--text); }
  .toast { position: fixed; bottom: 40px; left: 50%; transform: translateX(-50%); z-index: 80; background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--radius-control); padding: 10px 14px; box-shadow: var(--shadow-float); display: flex; gap: 8px; align-items: center; max-width: 90vw; }
</style>
