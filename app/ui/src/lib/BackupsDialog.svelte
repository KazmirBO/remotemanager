<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type BackupInfo } from './api';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { notify, refresh } from './store.svelte';

  let { onclose, onrestored }: { onclose: () => void; onrestored?: () => void } = $props();
  let backups = $state<BackupInfo[] | null>(null);
  let restoring = $state<number | null>(null);
  let password = $state('');
  let error = $state('');
  let busy = $state(false);

  onMount(() => {
    api.listBackups().then((b) => (backups = b)).catch((e) => (error = String(e)));
  });

  const fmt = (secs: number) => new Date(secs * 1000).toLocaleString('pl-PL');
  const kb = (n: number) => `${Math.max(1, Math.round(n / 1024))} KiB`;

  async function restore(e: Event) {
    e.preventDefault();
    if (restoring === null) return;
    busy = true;
    error = '';
    try {
      await api.restoreBackup(restoring, password);
      await refresh();
      notify('Przywrócono kopię zapasową.');
      onclose();
      onrestored?.();
    } catch (err) {
      error = String(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Kopie zapasowe" {onclose} width={520}>
  <p class="muted note">
    Przy każdym zapisie poprzednia wersja pliku trafia do kopii (liczbę kopii ustawisz w kategorii Bezpieczeństwo). Przywrócenie zastępuje obecną zawartość, a obecna wersja sama staje się kopią.
  </p>
  {#if backups === null}
    <p class="muted">Wczytywanie...</p>
  {:else if backups.length === 0}
    <div class="empty muted"><Icon name="clock" size={28} /><p>Brak kopii. Pojawią się po pierwszej zmianie.</p></div>
  {:else}
    <ul>
      {#each backups as b (b.n)}
        <li>
          <div><div>{fmt(b.modified)}</div><div class="muted mono">kopia {b.n} · {kb(b.size)}</div></div>
          <button class="btn compact" onclick={() => { restoring = b.n; password = ''; error = ''; }}>Przywróć</button>
        </li>
      {/each}
    </ul>
  {/if}
  {#if restoring !== null}
    <form id="restore-form" onsubmit={restore} class="restore">
      <div class="field">
        <label for="bk-pw">Hasło główne tej kopii (mogło być inne niż obecne)</label>
        <input id="bk-pw" type="password" bind:value={password} autocomplete="off" />
      </div>
      <button class="btn primary" disabled={busy || !password}>Przywróć kopię {restoring}</button>
    </form>
  {/if}
  {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
  {#snippet footer()}<button class="btn" onclick={onclose}>Zamknij</button>{/snippet}
</Modal>

<style>
  .note { font-size: 12px; margin: 0 0 14px; }
  ul { list-style: none; margin: 0 0 12px; padding: 0; border: 1px solid var(--border); border-radius: var(--radius-control); }
  li { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; min-height: 48px; }
  li + li { border-top: 1px solid var(--border); }
  .empty { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 24px; text-align: center; }
  .empty p { margin: 0; }
  .restore { margin-top: 12px; }
  .error { font-size: 13px; display: flex; gap: 6px; align-items: center; margin-top: 8px; }
</style>
