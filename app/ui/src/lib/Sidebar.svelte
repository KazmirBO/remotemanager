<script lang="ts">
  import { untrack } from 'svelte';
  import { api, type FolderView, type HostView, type Id } from './api';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { notify, openHost, refresh, ui } from './store.svelte';
  import { buildTree, descendantIds, edgeScrollSpeed, matches, plural, type FolderNode } from './tree';

  let {
    onNewHost, onNewFolder, onEditHost, onEditFolder, onExportFolder, onSettings, onSync, onLock,
  }: {
    onNewHost: (folder: Id | null) => void;
    onNewFolder: (parent: Id | null) => void;
    onEditHost: (h: HostView) => void;
    onEditFolder: (f: FolderView) => void;
    onExportFolder: (folder: Id) => void;
    onSettings: () => void;
    onSync: () => void;
    onLock: () => void;
  } = $props();

  type Sel = { kind: 'host' | 'folder'; id: Id } | null;
  let query = $state('');
  let selected = $state<Sel>(null);
  let menu = $state<{ x: number; y: number; target: Sel } | null>(null);
  let confirm = $state<{ kind: 'host' | 'folder'; id: Id; name: string; count: number } | null>(null);
  let dropTarget = $state<Id | 'root' | null>(null);

  const EXPANDED_KEY = 'mrm.expanded';
  const loadExpanded = (): Set<Id> => {
    try { return new Set(JSON.parse(localStorage.getItem(EXPANDED_KEY) ?? '[]')); } catch { return new Set(); }
  };
  let expanded = $state<Set<Id>>(loadExpanded());
  function toggle(id: Id) {
    const next = new Set(expanded);
    if (!next.delete(id)) next.add(id);
    expanded = next;
    try { localStorage.setItem(EXPANDED_KEY, JSON.stringify([...next])); } catch { /* brak pamięci lokalnej */ }
  }

  // Pokazanie hosta z zewnątrz (link): rozwijamy katalogi nad nim, zaznaczamy i przewijamy do niego.
  $effect(() => {
    const id = ui.reveal;
    if (!id) return;
    untrack(() => {
      ui.reveal = null;
      const h = (ui.doc?.hosts ?? []).find((x) => x.id === id);
      if (!h) return;
      const next = new Set(expanded);
      for (let f = h.folder; f; f = (ui.doc?.folders ?? []).find((x) => x.id === f)?.parent ?? null) next.add(f);
      expanded = next;
      query = '';
      selected = { kind: 'host', id };
      queueMicrotask(() => document.querySelector(`[data-host="${id}"]`)?.scrollIntoView({ block: 'nearest' }));
    });
  });

  // Poniżej 900 px pole wyszukiwania jest ukryte, więc filtr nie może zostać aktywny bez możliwości
  // wyczyszczenia go.
  $effect(() => {
    const narrow = matchMedia('(max-width: 899px)');
    const onChange = () => { if (narrow.matches) query = ''; };
    onChange();
    narrow.addEventListener('change', onChange);
    return () => narrow.removeEventListener('change', onChange);
  });

  const folders = $derived(ui.doc?.folders ?? []);
  const hosts = $derived(ui.doc?.hosts ?? []);
  const tree = $derived(buildTree(folders, hosts));
  const filtering = $derived(query.trim().length > 0);
  const favorites = $derived(hosts.filter((h) => h.favorite && matches(h, query)).sort((a, b) => a.name.localeCompare(b.name, 'pl')));

  const subtreeHasMatch = (n: FolderNode): boolean =>
    n.hosts.some((h) => matches(h, query)) || n.folders.some(subtreeHasMatch);
  const isOpen = (id: Id) => filtering || expanded.has(id);

  function openMenu(e: MouseEvent | KeyboardEvent, target: Sel, el?: HTMLElement) {
    e.preventDefault();
    const r = el?.getBoundingClientRect();
    const x = e instanceof MouseEvent ? e.clientX : (r?.left ?? 0) + 24;
    const y = e instanceof MouseEvent ? e.clientY : (r?.bottom ?? 0);
    menu = { x: Math.min(x, innerWidth - 220), y: Math.min(y, innerHeight - 260), target };
    selected = target;
  }
  const closeMenu = () => (menu = null);

  async function run(action: () => Promise<unknown>) {
    try { await action(); await refresh(); } catch (e) { notify(String(e), true); }
  }

  function askDelete(kind: 'host' | 'folder', id: Id) {
    if (kind === 'host') {
      confirm = { kind, id, name: hosts.find((h) => h.id === id)?.name ?? '', count: 0 };
    } else {
      const ids = descendantIds(folders, id);
      confirm = {
        kind, id, name: folders.find((f) => f.id === id)?.name ?? '',
        count: hosts.filter((h) => h.folder && ids.has(h.folder)).length,
      };
    }
  }
  async function doDelete() {
    const c = confirm;
    confirm = null;
    if (!c) return;
    await run(() => (c.kind === 'host' ? api.deleteHost(c.id) : api.deleteFolder(c.id)));
  }

  // Przeciąganie: host albo katalog na katalog (lub na tło = korzeń). Upuszczenie na host oznacza
  // jego katalog. Katalogu nie da się upuścić na siebie ani na własnego potomka.
  let dragging: { kind: 'host' | 'folder'; blocked: Set<Id> } | null = null;
  function dragStart(e: DragEvent, kind: 'host' | 'folder', id: Id) {
    e.dataTransfer?.setData('text/plain', JSON.stringify({ kind, id }));
    if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
    dragging = { kind, blocked: kind === 'folder' ? descendantIds(folders, id) : new Set() };
  }
  function dragEnd() {
    dragging = null;
    dropTarget = null;
    scrollSpeed = 0;
  }

  // Przewijanie listy podczas przeciągania: przeglądarka nie dostarcza wtedy zdarzeń kółka myszy, więc
  // lista przesuwa się sama, gdy przeciągany element jest przy jej górnej albo dolnej krawędzi.
  let treeEl: HTMLDivElement;
  let scrollSpeed = 0;
  let scrollFrame = 0;

  function dragScroll(e: DragEvent) {
    if (!dragging) return;
    const r = treeEl.getBoundingClientRect();
    scrollSpeed = edgeScrollSpeed(e.clientY, r.top, r.bottom);
    if (scrollSpeed && !scrollFrame) scrollFrame = requestAnimationFrame(scrollStep);
  }

  function scrollStep() {
    scrollFrame = 0;
    if (!dragging || !scrollSpeed) return;
    treeEl.scrollTop += scrollSpeed;
    scrollFrame = requestAnimationFrame(scrollStep);
  }
  function dragOver(e: DragEvent, target: Id | 'root') {
    e.stopPropagation();
    if (target !== 'root' && dragging?.blocked.has(target)) {
      // Bez preventDefault przeglądarka pokazuje, że tu nie wolno upuścić.
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'none';
      dropTarget = null;
      return;
    }
    e.preventDefault();
    dropTarget = target;
  }
  async function drop(e: DragEvent, target: Id | 'root') {
    e.preventDefault();
    e.stopPropagation();
    dropTarget = null;
    dragging = null;
    scrollSpeed = 0;
    let payload: { kind: 'host' | 'folder'; id: Id };
    try { payload = JSON.parse(e.dataTransfer?.getData('text/plain') ?? ''); } catch { return; }
    const dest = target === 'root' ? null : target;
    await run(() => (payload.kind === 'host' ? api.moveHost(payload.id, dest) : api.moveFolder(payload.id, dest)));
  }

  function rowKey(e: KeyboardEvent, kind: 'host' | 'folder', id: Id, el: HTMLElement) {
    if (e.key === 'Enter') {
      if (kind === 'host') { const h = hosts.find((x) => x.id === id); if (h) openHost(h); } else toggle(id);
    } else if (e.key === 'ContextMenu' || (e.key === 'F10' && e.shiftKey)) openMenu(e, { kind, id }, el);
    else if (e.key === 'ArrowRight' && kind === 'folder' && !expanded.has(id)) toggle(id);
    else if (e.key === 'ArrowLeft' && kind === 'folder' && expanded.has(id)) toggle(id);
    else if (e.key === 'Delete') askDelete(kind, id);
  }

  const syncLabels: Record<string, string> = {
    aktualny: 'plik aktualny', brak_pliku: 'brak pliku w folderze', lokalne_zmiany: 'lokalne zmiany do wysłania',
    zdalne_zmiany: 'dostępna nowsza wersja', konflikt: 'konflikt',
  };
  const syncLabel = $derived(!ui.sync?.folder ? 'wyłączona' : ui.sync.error ? 'błąd folderu' : syncLabels[ui.sync.status ?? ''] ?? '');
  // Kropka (kształt, nie kolor) oznacza, że coś czeka na uwagę.
  const syncPending = $derived(!!ui.sync?.folder && (!!ui.sync.error || (ui.sync.status !== null && ui.sync.status !== 'aktualny')));

  const menuHost = $derived(menu?.target?.kind === 'host' ? hosts.find((h) => h.id === menu!.target!.id) : undefined);
  const menuFolder = $derived(menu?.target?.kind === 'folder' ? folders.find((f) => f.id === menu!.target!.id) : undefined);

  async function copyAddress(address: string) {
    try {
      await navigator.clipboard.writeText(address);
      notify('Skopiowano adres.');
    } catch {
      notify('Nie udało się skopiować adresu.', true);
    }
  }
</script>

<!-- Prawy przycisk gdziekolwiek zamyka otwarte menu (faza przechwytywania), zanim element drzewa otworzy nowe. -->
<svelte:window onclick={closeMenu} oncontextmenucapture={closeMenu} onkeydown={(e) => e.key === 'Escape' && closeMenu()} />

{#snippet hostRow(h: HostView, depth: number)}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div
    class="row" data-host={h.id} class:sel={selected?.kind === 'host' && selected.id === h.id}
    role="treeitem" aria-selected={selected?.kind === 'host' && selected.id === h.id} tabindex="0"
    style="padding-left:{8 + depth * 16}px" title="{h.name} ({h.address})"
    draggable="true" ondragstart={(e) => dragStart(e, 'host', h.id)} ondragend={dragEnd}
    ondragover={(e) => dragOver(e, h.folder ?? 'root')} ondragleave={() => (dropTarget = null)} ondrop={(e) => drop(e, h.folder ?? 'root')}
    onclick={() => (selected = { kind: 'host', id: h.id })} ondblclick={() => openHost(h)}
    oncontextmenu={(e) => openMenu(e, { kind: 'host', id: h.id })}
    onkeydown={(e) => rowKey(e, 'host', h.id, e.currentTarget)}
  >
    <span class="chev"></span>
    <span class="badge {h.protocol}">{h.protocol.toUpperCase()}</span>
    <span class="label name">{h.name}</span>
    {#if h.favorite}<span class="label star"><Icon name="star" size={12} /></span>{/if}
  </div>
{/snippet}

{#snippet folderRow(n: FolderNode, depth: number)}
  {#if !filtering || subtreeHasMatch(n)}
    {@const open = isOpen(n.folder.id)}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div
      class="row" class:sel={selected?.kind === 'folder' && selected.id === n.folder.id} class:drop={dropTarget === n.folder.id}
      role="treeitem" aria-expanded={open} aria-selected={selected?.kind === 'folder' && selected.id === n.folder.id} tabindex="0"
      style="padding-left:{8 + depth * 16}px" title={n.folder.name}
      draggable="true" ondragstart={(e) => dragStart(e, 'folder', n.folder.id)} ondragend={dragEnd}
      ondragover={(e) => dragOver(e, n.folder.id)} ondragleave={() => (dropTarget = null)} ondrop={(e) => drop(e, n.folder.id)}
      onclick={() => { selected = { kind: 'folder', id: n.folder.id }; toggle(n.folder.id); }}
      oncontextmenu={(e) => openMenu(e, { kind: 'folder', id: n.folder.id })}
      onkeydown={(e) => rowKey(e, 'folder', n.folder.id, e.currentTarget)}
    >
      <span class="chev"><Icon name={open ? 'chevron-down' : 'chevron-right'} size={14} /></span>
      <Icon name={open ? 'folder-open' : 'folder'} size={16} />
      <span class="label name">{n.folder.name}</span>
    </div>
    {#if open}
      <div role="group">
        {#each n.folders as c (c.folder.id)}{@render folderRow(c, depth + 1)}{/each}
        {#each n.hosts.filter((h) => matches(h, query)) as h (h.id)}{@render hostRow(h, depth + 1)}{/each}
      </div>
    {/if}
  {/if}
{/snippet}

<aside>
  <div class="head">
    <div class="title label">Hosty</div>
    <div class="tools">
      <button class="icon-btn" aria-label="Nowy host" title="Nowy host" onclick={() => onNewHost(selected?.kind === 'folder' ? selected.id : null)}><Icon name="plus" /></button>
      <button class="icon-btn" aria-label="Nowy katalog" title="Nowy katalog" onclick={() => onNewFolder(selected?.kind === 'folder' ? selected.id : null)}><Icon name="folder" /></button>
    </div>
  </div>
  <div class="search label">
    <Icon name="search" size={14} />
    <input id="host-search" type="text" bind:value={query} placeholder="Szukaj" aria-label="Szukaj hostów" />
  </div>

  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="tree" class:drop={dropTarget === 'root'} role="tree" tabindex="-1" bind:this={treeEl}
    ondragovercapture={dragScroll}
    ondragover={(e) => dragOver(e, 'root')} ondragleave={() => (dropTarget = null)} ondrop={(e) => drop(e, 'root')}
    oncontextmenu={(e) => e.target === e.currentTarget && openMenu(e, null)}
  >
    {#if hosts.length === 0 && folders.length === 0}
      <!-- W trybie wąskim zostaje ikona i przycisk bez podpisu, żeby pusty panel nie był całkiem pusty. -->
      <div class="empty">
        <span class="label"><Icon name="host" size={28} /></span>
        <p class="label">Brak hostów.</p>
        <button class="btn compact" aria-label="Nowy host" title="Nowy host" onclick={() => onNewHost(null)}>
          <Icon name="plus" size={14} /><span class="label">Nowy host</span>
        </button>
      </div>
    {:else}
      {#if favorites.length}
        <!-- W trybie wąskim nagłówki znikają, więc ulubione (powtórzone niżej) też są ukryte. -->
        <div class="fav">
          <div class="section label">Ulubione</div>
          {#each favorites as h (h.id)}{@render hostRow(h, 0)}{/each}
          <div class="section label">Wszystkie</div>
        </div>
      {/if}
      {#each tree.roots as n (n.folder.id)}{@render folderRow(n, 0)}{/each}
      {#each tree.rootHosts.filter((h) => matches(h, query)) as h (h.id)}{@render hostRow(h, 0)}{/each}
      {#if filtering && !hosts.some((h) => matches(h, query))}
        <div class="empty label"><Icon name="search" size={28} /><p>Brak wyników dla „{query}”.</p></div>
      {/if}
    {/if}
  </div>

  <div class="foot">
    <button class="icon-btn" aria-label="Ustawienia" title="Ustawienia" onclick={onSettings}><Icon name="sliders" /></button>
    <button class="icon-btn sync" aria-label="Synchronizacja: {syncLabel}" title="Synchronizacja: {syncLabel}" onclick={onSync}>
      <Icon name={ui.sync?.status === 'konflikt' ? 'alert' : 'sync'} />
      {#if syncPending}<span class="dot"></span>{/if}
    </button>
    <button class="icon-btn" aria-label="Zablokuj" title="Zablokuj plik" onclick={onLock}><Icon name="lock" /></button>
  </div>
</aside>

{#if menu}
  <div class="menu" role="menu" style="left:{menu.x}px; top:{menu.y}px">
    {#if menuHost}
      <button role="menuitem" onclick={() => openHost(menuHost)}><Icon name="terminal" /> Połącz</button>
      <button role="menuitem" onclick={() => onEditHost(menuHost)}><Icon name="pencil" /> Edytuj</button>
      <button role="menuitem" onclick={() => run(() => api.setFavorite(menuHost.id, !menuHost.favorite))}>
        <Icon name="star" /> {menuHost.favorite ? 'Usuń z ulubionych' : 'Dodaj do ulubionych'}
      </button>
      <button role="menuitem" onclick={() => copyAddress(menuHost.address)}><Icon name="copy" /> Kopiuj adres</button>
      <hr />
      <button role="menuitem" class="danger" onclick={() => askDelete('host', menuHost.id)}><Icon name="trash" /> Usuń</button>
    {:else if menuFolder}
      <button role="menuitem" onclick={() => onNewHost(menuFolder.id)}><Icon name="plus" /> Nowy host tutaj</button>
      <button role="menuitem" onclick={() => onNewFolder(menuFolder.id)}><Icon name="folder" /> Nowy podkatalog</button>
      <button role="menuitem" onclick={() => onEditFolder(menuFolder)}><Icon name="sliders" /> Właściwości</button>
      <button role="menuitem" onclick={() => onExportFolder(menuFolder.id)}><Icon name="upload" /> Eksportuj...</button>
      <hr />
      <button role="menuitem" class="danger" onclick={() => askDelete('folder', menuFolder.id)}><Icon name="trash" /> Usuń</button>
    {:else}
      <button role="menuitem" onclick={() => onNewHost(null)}><Icon name="plus" /> Nowy host</button>
      <button role="menuitem" onclick={() => onNewFolder(null)}><Icon name="folder" /> Nowy katalog</button>
    {/if}
  </div>
{/if}

{#if confirm}
  <Modal title="Potwierdź usunięcie" onclose={() => (confirm = null)} width={440}>
    <p style="margin:0">
      {#if confirm.kind === 'host'}
        Usunąć hosta <b>{confirm.name}</b>? Tej operacji nie można cofnąć.
      {:else}
        Usunąć katalog <b>{confirm.name}</b> wraz z podkatalogami i {confirm.count} {plural(confirm.count, 'hostem', 'hostami', 'hostami')}? Tej operacji nie można cofnąć.
      {/if}
    </p>
    {#snippet footer()}
      <button class="btn" onclick={() => (confirm = null)}>Anuluj</button>
      <button class="btn danger" onclick={doDelete}><Icon name="trash" /> Usuń</button>
    {/snippet}
  </Modal>
{/if}

<style>
  aside { width: 300px; min-width: 56px; background: var(--panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; }
  .head { display: flex; align-items: center; justify-content: space-between; padding: 12px 12px 8px 16px; }
  .title { font-size: 16px; font-weight: 600; }
  .tools { display: flex; gap: 2px; }
  .search { display: flex; align-items: center; gap: 8px; margin: 0 12px 8px; padding: 0 10px; height: 32px; border: 1px solid var(--border-strong); border-radius: var(--radius-control); background: var(--surface); }
  .search input { border: none; background: transparent; height: 100%; padding: 0; outline: none; }
  .tree { flex: 1; overflow: auto; padding: 4px 6px; }
  .tree.drop { outline: 2px dashed var(--border-strong); outline-offset: -4px; }
  .section { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); padding: 10px 10px 4px; }
  .row { height: 32px; display: flex; align-items: center; gap: 8px; border-radius: var(--radius-control); cursor: default; user-select: none; padding-right: 8px; }
  .row:hover { background: var(--hover); }
  .row.sel { background: var(--hover); box-shadow: inset 0 0 0 1px var(--border-strong); }
  .row.drop { background: var(--hover); outline: 2px solid var(--accent); outline-offset: -2px; }
  .row:focus-visible { outline-offset: -2px; }
  .chev { width: 14px; display: inline-flex; flex-shrink: 0; }
  .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
  .star { color: var(--text-muted); display: inline-flex; }
  .empty { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 32px 12px; color: var(--text-muted); text-align: center; }
  .empty p { margin: 0; }
  .sync { position: relative; }
  .dot { position: absolute; top: 3px; right: 3px; width: 7px; height: 7px; border-radius: 50%; background: var(--accent); border: 1px solid var(--panel); }
  .foot { display: flex; gap: 4px; padding: 8px 12px; border-top: 1px solid var(--border); }

  /* Poniżej 900 px pasek boczny zwija się do ikon. */
  @media (max-width: 899px) {
    aside { width: 56px; }
    .label, .tools, .fav { display: none; }
    .empty { padding: 16px 0; }
    .head { justify-content: center; padding: 12px 0; }
    .foot { flex-direction: column; align-items: center; }
    .row { padding-left: 8px !important; justify-content: center; }
    .chev { display: none; }
  }
</style>
