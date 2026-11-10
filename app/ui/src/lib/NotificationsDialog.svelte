<script lang="ts">
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { ui } from './store.svelte';

  let { onclose }: { onclose: () => void } = $props();
</script>

<Modal title="Powiadomienia" {onclose} width={480}>
  {#if ui.history.length === 0}
    <div class="empty muted"><Icon name="bell" size={28} /><p>Brak powiadomień w tej sesji.</p></div>
  {:else}
    <ul>
      {#each ui.history as n (n.time + n.text)}
        <li>
          <span class="mono muted">{new Date(n.time).toLocaleTimeString('pl-PL')}</span>
          <span>{n.text}</span>
        </li>
      {/each}
    </ul>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (ui.history = [])} disabled={!ui.history.length}><Icon name="trash" /> Wyczyść</button>
    <button class="btn primary" onclick={onclose}>Zamknij</button>
  {/snippet}
</Modal>

<style>
  ul { list-style: none; margin: 0; padding: 0; border: 1px solid var(--border); border-radius: var(--radius-control); max-height: 50vh; overflow: auto; }
  li { display: flex; gap: 12px; padding: 10px 12px; align-items: baseline; }
  li + li { border-top: 1px solid var(--border); }
  .empty { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 24px; text-align: center; }
  .empty p { margin: 0; }
</style>
