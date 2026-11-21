<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from './api';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { ui } from './store.svelte';
  import { RELEASES_URL } from './updateCheck';

  let { onclose }: { onclose: () => void } = $props();
  let version = $state('0.1.0');
  let openError = $state('');

  async function openReleases() {
    openError = '';
    try {
      await api.openReleasesPage();
    } catch (e) {
      openError = String(e);
    }
  }

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
    {#if ui.update}
      <p class="update" role="status"><Icon name="info" size={14} /> Dostępna jest nowa wersja {ui.update}.</p>
    {/if}
    <button type="button" class="btn compact" onclick={openReleases}><Icon name="download" size={14} /> Strona wydań</button>
    <p class="muted small mono">{RELEASES_URL}</p>
    {#if openError}<p class="small" role="alert">{openError}</p>{/if}
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
  .update { display: flex; gap: 6px; align-items: center; font-weight: 600; }
  .mono { overflow-wrap: anywhere; user-select: text; }
</style>
