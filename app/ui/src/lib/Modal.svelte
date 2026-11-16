<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import { initialFocusIndex } from './focus';

  let {
    title, onclose, children, footer, width = 520, dismissible = true,
  }: {
    title: string; onclose: () => void; children: Snippet; footer?: Snippet;
    width?: number; dismissible?: boolean;
  } = $props();

  let dialog: HTMLDivElement;
  let previous: Element | null = null;

  $effect(() => {
    previous = document.activeElement;
    // Wyłączone elementy (np. przycisk główny okna zaufania przez pierwsze 500 ms) są pomijane;
    // bez aktywnego kandydata fokus dostaje samo okno, żeby Escape i Tab działały od razu.
    const found = [...dialog.querySelectorAll<HTMLElement>('input:not([type=hidden]), select, textarea, button.primary')];
    const i = initialFocusIndex(found.map((el) => ({ disabled: (el as HTMLButtonElement).disabled })));
    (i === null ? dialog : found[i]).focus();
    return () => {
      // Fokus wraca tylko wtedy, gdy nikt inny go nie przejął (np. terminal po nawiązaniu połączenia).
      const a = document.activeElement;
      if (!a || a === document.body) (previous as HTMLElement | null)?.focus?.();
    };
  });

  function keydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && dismissible) {
      e.stopPropagation();
      onclose();
    } else if (e.key === 'Tab') {
      // Pułapka fokusu wewnątrz okna.
      const items = [...dialog.querySelectorAll<HTMLElement>('button, input, select, textarea, [tabindex="0"]')].filter(
        (el) => !el.hasAttribute('disabled'),
      );
      if (!items.length) return;
      const first = items[0], last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="backdrop" onmousedown={(e) => e.target === e.currentTarget && dismissible && onclose()} onkeydown={keydown}>
  <div class="dialog" role="dialog" aria-modal="true" aria-label={title} tabindex="-1" bind:this={dialog} style="width:min({width}px, 94vw)">
    <header>
      <h2>{title}</h2>
      {#if dismissible}
        <button class="icon-btn" aria-label="Zamknij" onclick={onclose}><Icon name="close" /></button>
      {/if}
    </header>
    <div class="body">{@render children()}</div>
    {#if footer}<footer>{@render footer()}</footer>{/if}
  </div>
</div>

<style>
  .backdrop { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.55); display: flex; align-items: center; justify-content: center; z-index: 50; }
  .dialog { background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--radius-window); box-shadow: var(--shadow-float); max-height: 92vh; display: flex; flex-direction: column; }
  header { display: flex; align-items: center; justify-content: space-between; padding: 14px 24px; border-bottom: 1px solid var(--border); }
  h2 { margin: 0; font-size: 16px; font-weight: 600; }
  .body { padding: 20px 24px; overflow: auto; }
  footer { padding: 14px 24px; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 8px; }
</style>
