<script lang="ts" module>
  export interface TabItem { id: string; label: string; icon?: string; invalid?: boolean }
</script>

<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import { tabKeyTarget } from './tabNav';

  let {
    items, selected = $bindable(), label, idPrefix, orientation = 'horizontal', panel,
  }: {
    items: TabItem[];
    selected: string;
    label: string;
    idPrefix: string;
    orientation?: 'horizontal' | 'vertical';
    panel: Snippet<[string]>;
  } = $props();

  // Wybrana zakładka zniknęła (np. zmiana protokołu): wracamy do pierwszej.
  $effect(() => {
    if (items.length && !items.some((i) => i.id === selected)) selected = items[0].id;
  });

  function keydown(e: KeyboardEvent, index: number) {
    const to = tabKeyTarget(e.key, index, items.length, orientation);
    if (to === null) return;
    e.preventDefault();
    selected = items[to].id;
    document.getElementById(`${idPrefix}-tab-${items[to].id}`)?.focus();
  }
</script>

<div class="tabs {orientation}">
  <div class="list" role="tablist" aria-label={label} aria-orientation={orientation}>
    {#each items as item, i (item.id)}
      {@const active = item.id === selected}
      <button
        type="button" role="tab" class="tab" class:active
        id="{idPrefix}-tab-{item.id}" aria-selected={active} aria-controls="{idPrefix}-panel-{item.id}"
        tabindex={active ? 0 : -1}
        aria-label={item.invalid ? `${item.label}, zawiera błąd` : undefined}
        onclick={() => (selected = item.id)} onkeydown={(e) => keydown(e, i)}
      >
        {#if item.icon}<Icon name={item.icon} size={16} />{/if}
        <span class="text">{item.label}</span>
        {#if item.invalid}<span class="bad" title="Zawiera błąd"><Icon name="alert" size={12} /></span>{/if}
      </button>
    {/each}
  </div>
  <div class="panels">
    {#each items as item (item.id)}
      <div role="tabpanel" id="{idPrefix}-panel-{item.id}" aria-labelledby="{idPrefix}-tab-{item.id}" hidden={item.id !== selected}>
        {@render panel(item.id)}
      </div>
    {/each}
  </div>
</div>

<style>
  .tabs { display: flex; flex: 1; min-height: 0; }
  .tabs.horizontal { flex-direction: column; }
  .tabs.vertical { flex-direction: row; }
  .list { display: flex; }
  .horizontal .list { border-bottom: 1px solid var(--border); padding: 0 16px; overflow-x: auto; flex-shrink: 0; }
  .vertical .list { flex-direction: column; width: 176px; flex-shrink: 0; border-right: 1px solid var(--border); overflow-y: auto; padding: 8px; gap: 2px; }
  .tab {
    display: inline-flex; align-items: center; gap: 8px; height: 36px; padding: 0 12px; flex-shrink: 0;
    background: transparent; border: none; border-radius: var(--radius-control); text-align: left; white-space: nowrap;
  }
  .vertical .tab { width: 100%; }
  .tab:hover { background: var(--hover); }
  .tab.active { font-weight: 600; }
  .horizontal .tab.active { box-shadow: inset 0 -2px 0 var(--accent); border-radius: var(--radius-control) var(--radius-control) 0 0; }
  .vertical .tab.active { background: var(--hover); box-shadow: inset 2px 0 0 var(--accent); }
  .bad { display: inline-flex; margin-left: auto; }
  .horizontal .bad { margin-left: 0; }
  .panels { flex: 1; min-height: 0; overflow: auto; padding: 20px 24px; }
  [role='tabpanel'][hidden] { display: none; }
</style>
