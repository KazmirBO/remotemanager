<script lang="ts">
  import { onMount } from 'svelte';
  import { connectRdp, rdpClipboardFocus, rdpClose, rdpSend, type Id } from './api';
  import Icon from './Icon.svelte';
  import { scancodeFor } from './scancodes';
  import { matchAction } from './shortcuts';
  import { cancelPasswordPrompts, closeTab, host as hostById, modalOpen, needsPassword, notify, reconnect, requestPassword, ui } from './store.svelte';

  let { tabId, hostId, active }: { tabId: string; hostId: Id; active: boolean } = $props();

  let stage: HTMLDivElement;
  let canvas: HTMLCanvasElement;
  let status = $state<'connecting' | 'connected' | 'closed' | 'error'>('connecting');
  let message = $state('');
  let sessionId: string | null = null;
  const pressed = new Set<string>();
  /** Wciśnięte przyciski myszy (numeracja RDP), zwalniane przy utracie fokusu. */
  const buttons = new Set<number>();
  /** Niewysłana reszta przewijania z touchpada (w pikselach). */
  let wheelRest = { x: 0, y: 0 };
  let pendingMove: { x: number; y: number } | null = null;

  const send = (cmd: Parameters<typeof rdpSend>[1]) => sessionId && void rdpSend(sessionId, cmd);

  function toRemote(e: MouseEvent) {
    const r = canvas.getBoundingClientRect();
    const x = Math.round(((e.clientX - r.left) * canvas.width) / r.width);
    const y = Math.round(((e.clientY - r.top) * canvas.height) / r.height);
    return { x: Math.max(0, Math.min(canvas.width - 1, x)), y: Math.max(0, Math.min(canvas.height - 1, y)) };
  }

  function onMove(e: MouseEvent) {
    const first = pendingMove === null;
    pendingMove = toRemote(e);
    // Ruchy myszy są zbierane do jednej wiadomości na klatkę.
    if (first) {
      requestAnimationFrame(() => {
        if (pendingMove) send({ t: 'mouse_move', ...pendingMove });
        pendingMove = null;
      });
    }
  }

  function onButton(e: MouseEvent, down: boolean) {
    e.preventDefault();
    canvas.focus();
    const map: Record<number, number> = { 0: 0, 1: 1, 2: 2, 3: 3, 4: 4 };
    const button = map[e.button];
    if (button === undefined) return;
    if (down) buttons.add(button);
    else if (!buttons.delete(button)) return;
    send({ t: 'mouse_move', ...toRemote(e) });
    send({ t: 'mouse_button', button, down });
  }

  /** Liczba pełnych "ząbków" kółka z delty; reszta z płynnego przewijania czeka na kolejne zdarzenia. */
  function wheelSteps(delta: number, mode: number, axis: 'x' | 'y'): number {
    // Linie i strony przeliczamy na piksele; jeden ząbek to ok. 100 px.
    const px = mode === 1 ? delta * 40 : mode === 2 ? delta * 800 : delta;
    if (Math.abs(px) >= 50) {
      wheelRest[axis] = 0;
      return Math.sign(px) * Math.max(1, Math.round(Math.abs(px) / 100));
    }
    wheelRest[axis] += px;
    if (Math.abs(wheelRest[axis]) < 50) return 0;
    const steps = Math.sign(wheelRest[axis]);
    wheelRest[axis] = 0;
    return steps;
  }

  function onWheel(e: WheelEvent) {
    e.preventDefault();
    // Jeden ząbek kółka to 120 jednostek w RDP; szybkie przewijanie ograniczamy do 5 ząbków na zdarzenie.
    const y = Math.max(-5, Math.min(5, wheelSteps(e.deltaY, e.deltaMode, 'y')));
    const x = Math.max(-5, Math.min(5, wheelSteps(e.deltaX, e.deltaMode, 'x')));
    for (let i = 0; i < Math.abs(y); i++) send({ t: 'wheel', vertical: true, delta: -Math.sign(y) * 120 });
    for (let i = 0; i < Math.abs(x); i++) send({ t: 'wheel', vertical: false, delta: Math.sign(x) * 120 });
  }

  function onKey(e: KeyboardEvent, down: boolean) {
    // Skróty aplikacji (np. zamknięcie karty) zostają lokalne.
    if (matchAction(ui.doc?.settings, e)) return;
    const sc = scancodeFor(e.code);
    if (!sc) return;
    e.preventDefault();
    e.stopPropagation();
    if (down) pressed.add(e.code);
    else pressed.delete(e.code);
    send({ t: 'key', ...sc, down });
  }

  function releaseAll() {
    for (const code of pressed) {
      const sc = scancodeFor(code);
      if (sc) send({ t: 'key', ...sc, down: false });
    }
    pressed.clear();
    for (const button of buttons) send({ t: 'mouse_button', button, down: false });
    buttons.clear();
  }

  function resizeCanvas(w: number, h: number) {
    canvas.width = w;
    canvas.height = h;
  }

  let fullscreen = $state(false);
  async function toggleFullscreen() {
    try {
      const { getCurrentWindow } = await import('@tauri-apps/api/window');
      fullscreen = !fullscreen;
      await getCurrentWindow().setFullscreen(fullscreen);
    } catch {
      fullscreen = false;
    }
  }

  $effect(() => {
    if (active && status === 'connected') queueMicrotask(() => !modalOpen() && canvas?.focus());
    // Ukryta karta może nie dostać `blur`, więc wciśnięte klawisze zwalniamy też przy przełączeniu.
    if (!active) releaseAll();
  });

  onMount(() => {
    let disposed = false;
    const ctx = canvas.getContext('2d', { alpha: false })!;
    // Rozmiar pulpitu dopasowany do dostępnego miejsca (wielokrotność 4).
    const width = Math.max(200, Math.floor(stage.clientWidth / 4) * 4);
    const height = Math.max(200, Math.floor(stage.clientHeight / 4) * 4);
    resizeCanvas(width, height);

    const attempt = (password: string | null): Promise<string> =>
      connectRdp(
        hostId, width, height, password,
        (x, y, w, h, rgba) => ctx.putImageData(new ImageData(rgba as Uint8ClampedArray<ArrayBuffer>, w, h), x, y),
        (c) => {
          if (c.t === 'connected' || c.t === 'resized') {
            resizeCanvas(c.width, c.height);
            status = 'connected';
            if (active) queueMicrotask(() => !modalOpen() && canvas?.focus());
          } else if (c.t === 'notice') {
            notify(c.message);
          } else if (c.t === 'error') {
            status = 'error';
            message = c.message;
          } else {
            status = 'closed';
            message = `Sesja zakończona: ${c.reason}`;
          }
        },
      ).catch(async (e) => {
        // RDP z NLA wymaga hasła: bez zapisanego pytamy na tę sesję.
        const reason = needsPassword(e);
        if (reason === null || password !== null) throw e;
        const pw = await requestPassword(hostById(hostId)?.name ?? 'host', reason, tabId);
        if (pw === null || disposed) throw 'Anulowano łączenie.';
        return attempt(pw);
      });

    attempt(null)
      .then((id) => {
        if (disposed) void rdpClose(id);
        else sessionId = id;
      })
      .catch((e) => {
        status = 'error';
        message = String(e);
      });

    // Zmiana rozmiaru okna: po chwili spokoju prosimy serwer o pulpit pasujący do miejsca.
    let resizeTimer: ReturnType<typeof setTimeout> | undefined;
    const observer = new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (status !== 'connected' || !stage.clientWidth) return;
        const w = Math.max(200, Math.floor(stage.clientWidth / 4) * 4);
        const h = Math.max(200, Math.floor(stage.clientHeight / 4) * 4);
        if (w !== canvas.width || h !== canvas.height) send({ t: 'resize', width: w, height: h });
      }, 400);
    });
    observer.observe(stage);

    return () => {
      disposed = true;
      cancelPasswordPrompts(tabId);
      clearTimeout(resizeTimer);
      observer.disconnect();
      if (fullscreen) void import('@tauri-apps/api/window').then((m) => m.getCurrentWindow().setFullscreen(false)).catch(() => {});
      if (sessionId) void rdpClose(sessionId);
    };
  });
</script>

<svelte:window onblur={releaseAll} />

<div class="wrap" class:hidden={!active}>
  <div class="stage" bind:this={stage}>
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <canvas
      bind:this={canvas}
      tabindex="0"
      aria-label="Zdalny pulpit"
      onmousemove={onMove}
      onpointerdown={(e) => canvas.setPointerCapture(e.pointerId)}
      onmousedown={(e) => onButton(e, true)}
      onmouseup={(e) => onButton(e, false)}
      onwheel={onWheel}
      oncontextmenu={(e) => e.preventDefault()}
      onkeydown={(e) => onKey(e, true)}
      onkeyup={(e) => onKey(e, false)}
      onblur={() => {
        releaseAll();
        if (sessionId) void rdpClipboardFocus(sessionId, false);
      }}
      onfocus={() => sessionId && void rdpClipboardFocus(sessionId, true)}
    ></canvas>
  </div>
  {#if status === 'connected'}
    <div class="bar">
      <button class="icon-btn" title={fullscreen ? 'Wyjdź z pełnego ekranu' : 'Pełny ekran'} aria-label={fullscreen ? 'Wyjdź z pełnego ekranu' : 'Pełny ekran'} onclick={toggleFullscreen}>
        <Icon name="fullscreen" size={18} />
      </button>
      <button class="icon-btn" title="Ctrl+Alt+Del" aria-label="Wyślij Ctrl+Alt+Del" onclick={() => send({ t: 'ctrl_alt_del' })}>
        <Icon name="ctrl-alt-del" size={18} />
      </button>
    </div>
  {:else}
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
  .stage { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; overflow: hidden; }
  canvas { max-width: 100%; max-height: 100%; outline-offset: -2px; background: #000; cursor: default; }
  .bar { position: absolute; top: 8px; right: 8px; display: flex; gap: 4px; padding: 4px; background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--radius-control); opacity: 0.35; transition: opacity 0.15s; }
  .bar:hover, .bar:focus-within { opacity: 1; }
  .overlay { position: absolute; inset: 0; display: grid; place-items: center; background: color-mix(in srgb, var(--terminal) 80%, transparent); }
  .card { display: flex; flex-direction: column; align-items: center; gap: 12px; max-width: 460px; text-align: center; padding: 24px; border: 1px solid var(--border-strong); border-radius: var(--radius-window); background: var(--panel); }
  .card p { margin: 0; overflow-wrap: anywhere; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; }
</style>
