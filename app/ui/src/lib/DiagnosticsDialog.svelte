<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from './api';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { notify } from './store.svelte';

  let { onclose }: { onclose: () => void } = $props();
  let lines = $state<string[]>([]);

  const load = () => api.getDiagnostics().then((l) => (lines = l)).catch((e) => notify(String(e)));
  onMount(() => void load());

  /** Wpis ma postać "<sekundy epoki> <treść>". */
  function format(line: string) {
    const i = line.indexOf(' ');
    const secs = Number(line.slice(0, i));
    const text = line.slice(i + 1);
    return `${Number.isFinite(secs) ? new Date(secs * 1000).toLocaleTimeString('pl-PL') : '--:--:--'}  ${text}`;
  }
  const text = $derived(lines.map(format).join('\n'));
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      notify('Skopiowano dziennik.');
    } catch {
      notify('Nie udało się skopiować.');
    }
  }
  async function clear() {
    await api.clearDiagnostics();
    lines = [];
  }
</script>

<Modal title="Dziennik diagnostyczny" {onclose} width={680}>
  <p class="muted note"><Icon name="shield-check" size={14} /> Dziennik nie zawiera haseł ani kluczy: tylko zdarzenia (połączenia, błędy, synchronizacja). Żyje w pamięci do zamknięcia aplikacji.</p>
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <pre class="mono log" tabindex="0" aria-label="Wpisy dziennika">{text || 'Brak wpisów.'}</pre>
  {#snippet footer()}
    <button class="btn" onclick={load}><Icon name="refresh" /> Odśwież</button>
    <button class="btn" onclick={copy} disabled={!lines.length}><Icon name="copy" /> Kopiuj</button>
    <button class="btn" onclick={clear} disabled={!lines.length}><Icon name="trash" /> Wyczyść</button>
    <button class="btn primary" onclick={onclose}>Zamknij</button>
  {/snippet}
</Modal>

<style>
  .note { font-size: 12px; margin: 0 0 12px; display: flex; gap: 6px; align-items: flex-start; }
  .log { margin: 0; height: 320px; overflow: auto; background: var(--terminal); border: 1px solid var(--border); border-radius: var(--radius-control); padding: 10px; white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
