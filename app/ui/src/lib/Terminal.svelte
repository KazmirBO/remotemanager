<script lang="ts">
  import { onMount } from 'svelte';
  import { Terminal } from '@xterm/xterm';
  import { FitAddon } from '@xterm/addon-fit';
  import { api, connectSsh, sshWrite, type Id } from './api';
  import { closeTab, host as hostById, needsPassword, reconnect, requestPassword, ui } from './store.svelte';
  import { inherited } from './tree';
  import { terminalTheme } from './terminalThemes';
  import Icon from './Icon.svelte';

  let { tabId, hostId, active }: { tabId: string; hostId: Id; active: boolean } = $props();

  let el: HTMLDivElement;
  let status = $state<'connecting' | 'connected' | 'closed' | 'error'>('connecting');
  let message = $state('');
  let term: Terminal | undefined;
  let fit: FitAddon | undefined;
  let sessionId: string | null = null;
  const encoder = new TextEncoder();

  function refit() {
    if (!term || !fit || !el.offsetWidth) return;
    fit.fit();
    if (sessionId) void api.sshResize(sessionId, term.cols, term.rows).catch(() => {});
  }

  // Po przełączeniu na kartę kontener ma niezerowy rozmiar, więc dopasowujemy terminal.
  $effect(() => {
    if (active) queueMicrotask(() => { refit(); term?.focus(); });
  });

  onMount(() => {
    let disposed = false;
    const css = getComputedStyle(document.documentElement);
    // Schemat: własny dla hosta, odziedziczony z katalogu albo domyślny z ustawień.
    const h = hostById(hostId);
    const scheme =
      h?.fields.terminal_scheme ??
      (h ? (inherited(ui.doc?.folders ?? [], h.folder, 'terminal_scheme')?.value as string | undefined) : undefined) ??
      ui.doc?.settings.terminal_scheme ??
      'domyslny';
    term = new Terminal({
      fontFamily: "'JetBrains Mono', ui-monospace, monospace",
      fontSize: ui.doc?.settings.terminal_font_size ?? 13,
      cursorBlink: true,
      scrollback: 5000,
      theme: terminalTheme(scheme, css),
    });
    fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    fit.fit();

    term.onData((s) => sessionId && void sshWrite(sessionId, encoder.encode(s)));
    term.onBinary((s) => sessionId && void sshWrite(sessionId, Uint8Array.from(s, (c) => c.charCodeAt(0))));

    const observer = new ResizeObserver(() => refit());
    observer.observe(el);

    const attempt = (password: string | null): Promise<string> =>
      connectSsh(
        hostId,
        term!.cols,
        term!.rows,
        password,
        (bytes) => term?.write(bytes),
        (c) => {
          status = 'closed';
          message = c.t === 'exit' ? `Sesja zakończona (kod wyjścia ${c.code}).` : 'Połączenie zostało zamknięte.';
        },
      ).catch(async (e) => {
        // Brak agenta albo kluczy: pytamy o hasło tylko na tę sesję i próbujemy jeszcze raz.
        const reason = needsPassword(e);
        if (reason === null || password !== null) throw e;
        const pw = await requestPassword(h?.name ?? 'host', reason);
        if (pw === null) throw 'Anulowano łączenie.';
        return attempt(pw);
      });

    attempt(null)
      .then((id) => {
        if (disposed) {
          void api.sshClose(id);
          return;
        }
        sessionId = id;
        if (status === 'connecting') status = 'connected';
        refit();
        // Dialog zaufania oddaje fokus wierszowi drzewa, więc po połączeniu terminal przejmuje go z powrotem.
        if (active) term?.focus();
      })
      .catch((e) => {
        status = 'error';
        message = String(e);
      });

    return () => {
      disposed = true;
      observer.disconnect();
      if (sessionId) void api.sshClose(sessionId);
      term?.dispose();
    };
  });
</script>

<div class="wrap" class:hidden={!active}>
  <div class="term" bind:this={el}></div>
  {#if status !== 'connected'}
    <div class="overlay" role="status">
      <div class="card">
        {#if status === 'connecting'}
          <Icon name="plug" size={28} />
          <p>Łączenie...</p>
        {:else}
          <Icon name={status === 'error' ? 'alert' : 'link-off'} size={28} />
          <p>{message}</p>
          <div class="actions">
            <button class="btn primary" onclick={() => reconnect(tabId)}><Icon name="refresh" /> Połącz ponownie</button>
            <button class="btn" onclick={() => closeTab(tabId)}>Zamknij kartę</button>
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .wrap { position: absolute; inset: 0; background: var(--terminal); }
  .wrap.hidden { visibility: hidden; pointer-events: none; }
  .term { position: absolute; inset: 8px 0 0 8px; }
  .overlay { position: absolute; inset: 0; display: grid; place-items: center; background: color-mix(in srgb, var(--terminal) 80%, transparent); }
  .card { display: flex; flex-direction: column; align-items: center; gap: 12px; max-width: 460px; text-align: center; padding: 24px; border: 1px solid var(--border-strong); border-radius: var(--radius-window); background: var(--panel); }
  .card p { margin: 0; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; }
</style>
