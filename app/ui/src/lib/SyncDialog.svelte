<script lang="ts">
  import { api, type SyncStatus } from './api';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { onLocked, notify, refreshSync, ui } from './store.svelte';

  let { onclose }: { onclose: () => void } = $props();
  // svelte-ignore state_referenced_locally
  let folder = $state(ui.sync?.folder ?? '');
  let error = $state('');
  let busy = $state(false);

  const texts: Record<SyncStatus, string> = {
    aktualny: 'Plik jest aktualny.',
    brak_pliku: 'W folderze nie ma jeszcze pliku. Pierwsza synchronizacja wyśle lokalny plik.',
    lokalne_zmiany: 'Lokalny plik ma zmiany do wysłania.',
    zdalne_zmiany: 'W folderze jest nowsza wersja pliku. Pobranie zablokuje plik, odblokujesz go hasłem głównym.',
    konflikt: 'Plik zmieniono po obu stronach. Wybierz, którą wersję zachować. Druga zostanie zapisana jako kopia konfliktu.',
  };

  async function run(action: () => Promise<unknown>) {
    busy = true;
    error = '';
    try {
      await action();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
      await refreshSync();
    }
  }

  const setFolder = () => run(async () => { await api.syncSetFolder(folder.trim() || null); });
  const sync = (keep?: 'local' | 'remote') =>
    run(async () => {
      const r = await api.syncRun(keep);
      if (r.locked) {
        notify('Pobrano zdalną wersję. Odblokuj plik hasłem głównym.');
        onclose();
        onLocked();
      } else {
        notify('Synchronizacja zakończona.');
      }
    });
</script>

<Modal title="Synchronizacja" {onclose} width={560}>
  <p class="muted note">
    Zaszyfrowany plik jest kopiowany do wskazanego folderu (np. zsynchronizowanego przez Syncthing, Nextcloud albo dysk sieciowy). Zawartość
    pozostaje zaszyfrowana hasłem głównym.
  </p>
  <div class="field">
    <label for="sy-folder">Folder synchronizacji</label>
    <div class="row">
      <input id="sy-folder" type="text" bind:value={folder} placeholder="/ścieżka/do/folderu" class="mono" />
      <button class="btn" onclick={setFolder} disabled={busy}>{folder.trim() ? 'Ustaw' : 'Wyłącz'}</button>
    </div>
  </div>

  {#if ui.sync?.folder}
    <div class="state" role="status">
      <Icon name={ui.sync.status === 'konflikt' ? 'alert' : ui.sync.status === 'aktualny' ? 'check-circle' : 'sync'} size={20} />
      <span>{ui.sync.error ?? (ui.sync.status ? texts[ui.sync.status] : '')}</span>
    </div>
    {#if ui.sync.status === 'konflikt'}
      <div class="actions">
        <button class="btn" disabled={busy} onclick={() => sync('local')}><Icon name="upload" /> Zachowaj lokalną</button>
        <button class="btn" disabled={busy} onclick={() => sync('remote')}><Icon name="download" /> Zachowaj zdalną</button>
      </div>
    {:else}
      <div class="actions">
        <button class="btn primary" disabled={busy || !!ui.sync.error} onclick={() => sync()}><Icon name="sync" /> Synchronizuj teraz</button>
      </div>
    {/if}
  {/if}
  {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
  {#snippet footer()}
    <button class="btn" onclick={onclose}>Zamknij</button>
  {/snippet}
</Modal>

<style>
  .note { font-size: 12px; margin: 0 0 16px; }
  .row { display: flex; gap: 8px; }
  .state { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--border-strong); border-radius: var(--radius-control); padding: 12px; margin-bottom: 12px; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .error { margin-top: 12px; font-size: 13px; display: flex; gap: 6px; align-items: center; }
</style>
