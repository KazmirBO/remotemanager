<script lang="ts">
  import Icon from './Icon.svelte';
  import { openHost, ui } from './store.svelte';
  import { matches } from './tree';
  import type { HostView } from './api';

  let { onclose, onlink }: { onclose: () => void; onlink: (url: string) => void } = $props();
  let query = $state('');
  let index = $state(0);
  let input: HTMLInputElement;

  const isLink = $derived(/^(ssh|rdp):\/\//i.test(query.trim()));
  const results = $derived(
    (ui.doc?.hosts ?? [])
      .filter((h) => matches(h, query))
      .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.name.localeCompare(b.name, 'pl'))
      .slice(0, 8),
  );
  $effect(() => { query; index = 0; });
  $effect(() => input.focus());

  function choose(h: HostView) {
    openHost(h);
    onclose();
  }
  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
    else if (e.key === 'ArrowDown') { e.preventDefault(); index = Math.min(index + 1, results.length - 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); index = Math.max(index - 1, 0); }
    else if (e.key === 'Enter' && isLink) { onlink(query.trim()); onclose(); }
    else if (e.key === 'Enter' && results[index]) choose(results[index]);
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="backdrop" onmousedown={(e) => e.target === e.currentTarget && onclose()} onkeydown={key}>
  <div class="box" role="dialog" aria-modal="true" aria-label="Szybkie łączenie">
    <div class="search">
      <Icon name="search" size={16} />
      <input bind:this={input} bind:value={query} type="text" placeholder="Szukaj hosta albo wklej link ssh:// lub rdp://" aria-label="Szukaj hosta" />
    </div>
    <ul role="listbox">
      {#if isLink}
        <li role="option" aria-selected="true">
          <button class="sel" onclick={() => { onlink(query.trim()); onclose(); }}>
            <Icon name="link" size={16} />
            <span class="name">Otwórz link</span>
            <span class="addr mono muted">{query.trim()}</span>
          </button>
        </li>
      {/if}
      {#each results as h, i (h.id)}
        <li role="option" aria-selected={i === index}>
          <button class:sel={i === index} onclick={() => choose(h)} onmousemove={() => (index = i)}>
            <span class="badge {h.protocol}">{h.protocol.toUpperCase()}</span>
            <span class="name">{h.name}</span>
            <span class="addr mono muted">{h.address}</span>
          </button>
        </li>
      {:else}
        {#if !isLink}<li class="empty muted">Brak wyników.</li>{/if}
      {/each}
    </ul>
  </div>
</div>

<style>
  .backdrop { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.45); display: flex; justify-content: center; padding-top: 12vh; z-index: 60; }
  .box { width: min(560px, 94vw); height: fit-content; background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--radius-window); box-shadow: var(--shadow-float); overflow: hidden; }
  .search { display: flex; align-items: center; gap: 10px; padding: 0 14px; border-bottom: 1px solid var(--border); }
  .search input { border: none; background: transparent; height: 48px; padding: 0; outline: none; }
  ul { list-style: none; margin: 0; padding: 6px; max-height: 50vh; overflow: auto; }
  li button { width: 100%; height: 44px; display: flex; align-items: center; gap: 10px; padding: 0 10px; background: transparent; border: none; border-radius: var(--radius-control); text-align: left; }
  li button.sel { background: var(--hover); }
  .name { font-weight: 500; }
  .addr { margin-left: auto; }
  .empty { padding: 14px; text-align: center; }
</style>
