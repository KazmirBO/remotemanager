<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';

  let { onclose }: { onclose: () => void } = $props();
  let version = $state('0.1.0');

  onMount(async () => {
    try {
      const { getVersion } = await import('@tauri-apps/api/app');
      version = await getVersion();
    } catch {
      /* poza Tauri zostaje wartość domyślna */
    }
  });
</script>

<Modal title="O programie" {onclose} width={440}>
  <div class="about">
    <div class="logo"><Icon name="terminal" size={28} /></div>
    <h3>Menedżer sesji</h3>
    <p class="muted">Wersja {version}</p>
    <p>Klient SSH i RDP z drzewem hostów, zaszyfrowanym plikiem i synchronizacją przez folder.</p>
    <p class="muted small">Licencja MIT lub Apache-2.0. Hasła i klucze prywatne są zapisane tylko w pliku zaszyfrowanym hasłem głównym; poza tę maszynę trafiają wyłącznie do folderu synchronizacji, jeśli go ustawisz.</p>
  </div>
  {#snippet footer()}<button class="btn primary" onclick={onclose}>Zamknij</button>{/snippet}
</Modal>

<style>
  .about { display: flex; flex-direction: column; align-items: center; text-align: center; gap: 4px; }
  .logo { width: 56px; height: 56px; display: grid; place-items: center; border: 1px solid var(--border-strong); border-radius: var(--radius-menu); margin-bottom: 8px; }
  h3 { margin: 0; font-size: 18px; font-weight: 600; }
  p { margin: 4px 0; }
  .small { font-size: 12px; }
</style>
