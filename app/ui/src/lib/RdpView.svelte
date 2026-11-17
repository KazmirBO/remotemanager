<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import { connectRdp, rdpClipboardFocus, rdpClose, rdpGrabKeys, rdpSend, type Id, type RdpControl } from './api';
  import Icon from './Icon.svelte';
  import { DEFAULT_BAR, anchorBar, barStyle, clampBar } from './rdpBar';
  import { desktopSize } from './rdpSize';
  import { scancodeFor } from './scancodes';
  import { createSerialQueue, grabActive, grabWanted, keyRoute, parseRelease } from './rdpKeys';
  import { validPointer } from './rdpPointer';
  import { binding, matchAction } from './shortcuts';
  import { cancelPasswordPrompts, closeTab, host as hostById, modalOpen, needsPassword, notify, reconnect, requestPassword, setRdpBar, ui } from './store.svelte';

  let { tabId, hostId, active }: { tabId: string; hostId: Id; active: boolean } = $props();

  let wrap: HTMLDivElement;
  let stage: HTMLDivElement;
  let canvas: HTMLCanvasElement;
  let status = $state<'connecting' | 'connected' | 'closed' | 'error'>('connecting');
  let message = $state('');
  let sessionId = $state<string | null>(null);
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
    // Skróty aplikacji (np. zamknięcie karty) zostają lokalne, chyba że sesja przechwytuje klawisze:
    // wtedy poza skrótem zwalniającym wszystko idzie do zdalnego pulpitu.
    const route = keyRoute(matchAction(ui.doc?.settings, e), grabbing);
    if (route === 'app') return;
    if (route === 'release') {
      e.preventDefault();
      e.stopPropagation();
      if (down && !e.repeat) {
        releaseAll();
        manual = false;
      }
      return;
    }
    const sc = scancodeFor(e.code);
    // W trybie przechwytywania klawisz bez scancode też jest zatrzymany, żeby nie wykonał skrótu aplikacji.
    if (!sc) {
      if (grabbing) {
        e.preventDefault();
        e.stopPropagation();
      }
      return;
    }
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

  // Obraz jest zawsze rysowany 1:1, bez skalowania. Za rozmiarem okna podąża rozdzielczość zdalnego
  // pulpitu (prośba do serwera po chwili spokoju). Dopóki serwer jej nie zmieni albo gdy zmiany nie
  // obsługuje, mniejszy pulpit zostaje w lewym górnym rogu, a większy da się przewijać.
  function resizeCanvas(w: number, h: number) {
    canvas.width = w;
    canvas.height = h;
  }

  /** Miejsce na pulpit w oknie. Wymiary zewnętrzne, razem z paskami przewijania: liczone bez nich
   * dałyby mniejszy pulpit, po którego ustawieniu paski znikają i trzeba by prosić serwer drugi raz. */
  const room = () => ({ width: stage.offsetWidth, height: stage.offsetHeight });

  let fullscreen = $state(false);

  // Panel z przyciskami da się przesunąć uchwytem, bo w stałym miejscu zasłaniał elementy zdalnego
  // pulpitu. Miejsce jest wspólne dla kart i zapamiętane (`ui.rdpBar`); `drag` to lewy górny róg
  // panelu w trakcie przeciągania.
  let bar = $state<HTMLDivElement>();
  let barWidth = $state(0);
  let barHeight = $state(0);
  let drag = $state<{ left: number; top: number } | null>(null);
  /** Punkt chwytu względem rogu panelu i to, czy panel faktycznie się przesunął. */
  let grip = { dx: 0, dy: 0, moved: false };
  const barCss = $derived(
    drag ? `left: ${drag.left}px; top: ${drag.top}px;` : barStyle(ui.rdpBar, { width: barWidth, height: barHeight }),
  );
  const barSize = () => ({ width: bar?.offsetWidth ?? 0, height: bar?.offsetHeight ?? 0 });
  const viewSize = () => ({ width: wrap.clientWidth, height: wrap.clientHeight });

  function onGripDown(e: PointerEvent) {
    if (e.button !== 0 || !bar) return;
    const b = bar.getBoundingClientRect();
    const w = wrap.getBoundingClientRect();
    grip = { dx: e.clientX - b.left, dy: e.clientY - b.top, moved: false };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    drag = clampBar(b.left - w.left, b.top - w.top, barSize(), viewSize());
  }

  function onGripMove(e: PointerEvent) {
    if (!drag) return;
    const w = wrap.getBoundingClientRect();
    const next = clampBar(e.clientX - w.left - grip.dx, e.clientY - w.top - grip.dy, barSize(), viewSize());
    if (next.left === drag.left && next.top === drag.top) return;
    grip.moved = true;
    drag = next;
  }

  function onGripUp() {
    if (!drag) return;
    // Samo kliknięcie uchwytu niczego nie zapisuje.
    if (grip.moved) setRdpBar(anchorBar(drag.left, drag.top, barSize(), viewSize()));
    drag = null;
    canvas.focus();
  }

  // Panel znika razem z połączeniem; przerwane przeciąganie nie może zostać jako jego położenie.
  $effect(() => {
    if (status !== 'connected') drag = null;
  });

  // Tryb przechwytywania klawiszy. `manual` to wybór użytkownika dla tej sesji (przycisk albo skrót
  // zwalniający) i ma pierwszeństwo przed ustawieniem; `null` oznacza brak wyboru.
  let manual = $state<boolean | null>(null);
  let focused = $state(false);
  let modal = $state(false);
  const wanted = $derived(grabWanted(ui.doc?.settings.rdp_keys ?? 'never', manual, fullscreen));
  const grabbing = $derived(grabActive(wanted, { connected: status === 'connected', tabActive: active, focused, modal }));
  const releaseKey = $derived(binding(ui.doc?.settings, 'release_keys'));
  // Czy backend ma teraz przejętą klawiaturę tej sesji, i czy ostrzeżenie o klawiszach systemowych już padło.
  let grabbed = false;
  let warnedSystem = false;
  // Wywołania `rdp_grab_keys` idą po kolei: każde jest osobnym zadaniem w backendzie i bez kolejki
  // wyłączenie mogłoby je wyprzedzić. `grabGen` unieważnia wynik włączenia, które wyłączono w międzyczasie.
  const grabQueue = createSerialQueue();
  let grabGen = 0;

  function setGrab(on: boolean) {
    if (on === grabbed || !sessionId) return;
    grabbed = on;
    const id = sessionId;
    const gen = ++grabGen;
    if (on) {
      const release = parseRelease(releaseKey);
      void grabQueue(() => rdpGrabKeys(id, true, release)).then((r) => {
        // Błąd wywołania (r === null) albo tryb wyłączony w międzyczasie: bez powiadomienia.
        if (!r || r.system || warnedSystem || gen !== grabGen || !grabbed) return;
        warnedSystem = true;
        notify('Klawisze systemowe (Windows, Alt+Tab) zostają lokalne. Pozostałe skróty trafiają do zdalnego pulpitu.');
      });
    } else {
      releaseAll();
      void grabQueue(() => rdpGrabKeys(id, false, null));
    }
  }

  $effect(() => {
    const on = grabbing && sessionId !== null;
    untrack(() => setGrab(on));
  });

  /** Wskaźnik myszy zdalnego pulpitu jako kursor CSS kanwy; dane niepoprawne dają kursor domyślny. */
  function applyPointer(c: RdpControl) {
    if (c.t === 'pointer_hidden') {
      canvas.style.cursor = 'none';
      return;
    }
    canvas.style.cursor = '';
    if (c.t !== 'pointer') return;
    const p = validPointer(c);
    if (!p) return;
    try {
      const tmp = document.createElement('canvas');
      tmp.width = p.width;
      tmp.height = p.height;
      tmp.getContext('2d')!.putImageData(new ImageData(Uint8ClampedArray.from(p.rgba), p.width, p.height), 0, 0);
      canvas.style.cursor = `url(${tmp.toDataURL()}) ${p.hot_x} ${p.hot_y}, default`;
    } catch {
      canvas.style.cursor = '';
    }
  }
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
    // Rozmiar pulpitu dopasowany do dostępnego miejsca.
    const first = room();
    const { width, height } = desktopSize(first.width, first.height);
    resizeCanvas(width, height);

    // Prośba do serwera o pulpit pasujący do miejsca, po chwili spokoju. Ten sam rozmiar nie jest
    // wysyłany drugi raz: serwer, który go nie przyjął albo przyciął do własnego limitu, odpowiadałby
    // w kółko tą samą reaktywacją sesji.
    let resizeTimer: ReturnType<typeof setTimeout> | undefined;
    let requested = `${width}x${height}`;
    const scheduleResize = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        const box = room();
        // Ukryta karta albo okno w trakcie zwijania nie mają wymiarów.
        if (status !== 'connected' || !box.width || !box.height) return;
        const want = desktopSize(box.width, box.height);
        const key = `${want.width}x${want.height}`;
        if (key === requested || (want.width === canvas.width && want.height === canvas.height)) return;
        requested = key;
        send({ t: 'resize', ...want });
      }, 400);
    };

    const attempt = (password: string | null): Promise<string> =>
      connectRdp(
        hostId, width, height, password,
        (x, y, w, h, rgba) => ctx.putImageData(new ImageData(rgba as Uint8ClampedArray<ArrayBuffer>, w, h), x, y),
        (c) => {
          if (c.t === 'connected' || c.t === 'resized') {
            resizeCanvas(c.width, c.height);
            status = 'connected';
            // Okno mogło zmienić rozmiar w trakcie łączenia albo reaktywacji sesji.
            scheduleResize();
            if (active) queueMicrotask(() => !modalOpen() && canvas?.focus());
          } else if (c.t === 'notice') {
            notify(c.message);
          } else if (c.t === 'pointer' || c.t === 'pointer_default' || c.t === 'pointer_hidden') {
            applyPointer(c);
          } else if (c.t === 'error') {
            status = 'error';
            message = c.message;
          } else if (c.t === 'closed') {
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
        if (disposed) {
          void rdpClose(id);
          return;
        }
        sessionId = id;
        // Identyfikator nie jest stanem reaktywnym, a komunikat o połączeniu mógł przyjść przed nim:
        // tryb przechwytywania wynikający z ustawienia trzeba wtedy włączyć tutaj.
        setGrab(grabbing);
      })
      .catch((e) => {
        status = 'error';
        message = String(e);
      });

    // Zmiana rozmiaru okna: po chwili spokoju prosimy serwer o pulpit pasujący do miejsca.
    const observer = new ResizeObserver(scheduleResize);
    observer.observe(stage);

    // Okno modalne zabiera fokus kanwie, ale stan sprawdzamy też jawnie, przy każdej zmianie fokusu.
    // Odroczone: focusout wywołuje też usuwanie elementu z DOM w trakcie aktualizacji szablonu.
    const checkModal = () => queueMicrotask(() => (modal = modalOpen()));
    document.addEventListener('focusin', checkModal);
    document.addEventListener('focusout', checkModal);

    // Backend zwolnił przechwycone klawisze. Skrót zwalniający (rozpoznany przez hak) wyłącza tryb
    // dla sesji jak przycisk. Utrata pierwszego planu trybu nie wyłącza: po powrocie fokusu na kanwę
    // przechwytywanie włączy się ponownie. Hak zdjęty przez system wymaga ponownego włączenia.
    const unlisten = listen<{ id: string; reason?: 'combo' | 'foreground' | 'hook_lost' }>('rdp-keys-released', (e) => {
      if (e.payload.id !== sessionId) return;
      grabbed = false;
      releaseAll();
      const reason = e.payload.reason ?? 'combo';
      if (reason === 'foreground') return;
      manual = false;
      if (reason === 'hook_lost') notify('System przerwał przechwytywanie klawiszy. Włącz je ponownie przyciskiem na pasku sesji.');
    });

    return () => {
      disposed = true;
      cancelPasswordPrompts(tabId);
      clearTimeout(resizeTimer);
      observer.disconnect();
      document.removeEventListener('focusin', checkModal);
      document.removeEventListener('focusout', checkModal);
      void unlisten.then((f) => f()).catch(() => {});
      // Backend nie może zostać z przejętą klawiaturą po zamknięciu widoku.
      if (grabbed && sessionId) {
        const id = sessionId;
        void grabQueue(() => rdpGrabKeys(id, false, null));
      }
      grabbed = false;
      grabGen++;
      if (fullscreen) void import('@tauri-apps/api/window').then((m) => m.getCurrentWindow().setFullscreen(false)).catch(() => {});
      if (sessionId) void rdpClose(sessionId);
    };
  });
</script>

<!-- Powrót okna na pierwszy plan: po zwolnieniu klawiszy przez backend (powód `foreground`) kanwa mogła
  nie stracić fokusu, więc żaden stan się nie zmienił; przejęcie włączamy tu ponownie, jeśli nadal jest chciane. -->
<svelte:window onblur={releaseAll} onfocus={() => setGrab(grabbing)} />

<div class="wrap" class:hidden={!active} bind:this={wrap}>
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
        focused = false;
        releaseAll();
        if (sessionId) void rdpClipboardFocus(sessionId, false);
      }}
      onfocus={() => {
        focused = true;
        modal = modalOpen();
        if (sessionId) void rdpClipboardFocus(sessionId, true);
      }}
    ></canvas>
  </div>
  {#if status === 'connected'}
    <div class="bar" class:dragging={drag !== null} style={barCss} bind:this={bar} bind:offsetWidth={barWidth} bind:offsetHeight={barHeight}>
      <!-- Uchwyt jest tylko dla myszy: panel zasłania cele kliknięć, a klawiaturą się go nie omija. -->
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div
        class="grip"
        aria-hidden="true"
        title="Przeciągnij, aby przesunąć panel. Dwukrotne kliknięcie przywraca miejsce domyślne."
        onpointerdown={onGripDown}
        onpointermove={onGripMove}
        onpointerup={onGripUp}
        onpointercancel={onGripUp}
        ondblclick={() => {
          setRdpBar({ ...DEFAULT_BAR });
          canvas.focus();
        }}
      ></div>
      <button class="icon-btn" title={fullscreen ? 'Wyjdź z pełnego ekranu' : 'Pełny ekran'} aria-label={fullscreen ? 'Wyjdź z pełnego ekranu' : 'Pełny ekran'} onclick={toggleFullscreen}>
        <Icon name="fullscreen" size={18} />
      </button>
      <button
        class="icon-btn toggle"
        class:on={wanted}
        aria-pressed={wanted}
        title={`Przechwytywanie klawiszy: ${wanted ? 'włączone' : 'wyłączone'}. Zwolnienie: ${releaseKey}`}
        aria-label={`Przechwytywanie klawiszy (zwolnienie: ${releaseKey})`}
        onclick={() => {
          manual = !wanted;
          canvas.focus();
        }}
      >
        <Icon name="keyboard" size={18} />
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
  /* Pulpit większy od okna (serwer bez zmiany rozdzielczości) da się przewijać, zamiast go zmniejszać. */
  .stage { position: absolute; inset: 0; overflow: auto; }
  /* Bez `max-width`: obraz jest zawsze 1:1. */
  canvas { display: block; outline-offset: -2px; background: #000; cursor: default; }
  /* Miejsce panelu (krawędzie i odległości) ustawia styl elementu, patrz `barStyle`. */
  .bar { position: absolute; display: flex; gap: 4px; padding: 4px; background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--radius-control); opacity: 0.35; transition: opacity 0.15s; }
  /* Stan włączony: wypełnienie akcentem i pogrubione obramowanie, nie sam kolor. */
  .icon-btn.toggle.on { background: var(--accent); color: var(--on-accent); border-color: var(--text); box-shadow: inset 0 0 0 1px var(--on-accent); }
  .icon-btn.toggle.on:hover:not(:disabled) { background: var(--accent); filter: brightness(1.1); }
  .bar:hover, .bar:focus-within, .bar.dragging { opacity: 1; }
  .bar.dragging { transition: none; }
  /* Uchwyt: dwie kolumny kropek. `touch-action: none`, żeby przeciąganie dotykiem nie przewijało widoku. */
  .grip { width: 12px; align-self: stretch; cursor: grab; touch-action: none; user-select: none; border-radius: var(--radius-badge);
    background-image: radial-gradient(circle, var(--text-muted) 1px, transparent 1.5px), radial-gradient(circle, var(--text-muted) 1px, transparent 1.5px);
    background-size: 4px 6px; background-repeat: repeat-y; background-position: 2px center, 7px center; }
  .grip:hover { background-color: var(--hover); }
  .bar.dragging .grip { cursor: grabbing; }
  .overlay { position: absolute; inset: 0; display: grid; place-items: center; background: color-mix(in srgb, var(--terminal) 80%, transparent); }
  .card { display: flex; flex-direction: column; align-items: center; gap: 12px; max-width: 460px; text-align: center; padding: 24px; border: 1px solid var(--border-strong); border-radius: var(--radius-window); background: var(--panel); }
  .card p { margin: 0; overflow-wrap: anywhere; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; }
</style>
