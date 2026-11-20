<script lang="ts">
  import { api, type SyncStatus } from '../api';
  import Icon from '../Icon.svelte';
  import { onLocked, notify, refreshSync, ui } from '../store.svelte';
  import { changeText, diffCount, diffGroups, diffIntro, diffIsEmpty, extraLines, type SyncDiff } from '../syncDiff';

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

  // Różnice między wersją lokalną a plikiem z folderu; lista znika po każdej operacji, bo stan się zmienia.
  let diff = $state<SyncDiff | null>(null);
  const canDiff = $derived(
    !!ui.sync?.folder && !ui.sync.error
      && (ui.sync.status === 'lokalne_zmiany' || ui.sync.status === 'zdalne_zmiany' || ui.sync.status === 'konflikt'),
  );
  const groups = $derived(diff?.diff ? diffGroups(diff.diff) : []);
  const extras = $derived(diff?.diff ? extraLines(diff.diff) : []);

  async function toggleDiff() {
    if (diff) { diff = null; return; }
    busy = true;
    error = '';
    try {
      diff = await api.syncDiff();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function run(action: () => Promise<unknown>) {
    busy = true;
    error = '';
    diff = null;
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

  <p class="form-note">Działania w tej kategorii wykonują się od razu, przycisk Zapisz ich nie dotyczy.</p>
  <p class="muted note">
    Zaszyfrowany plik jest kopiowany do wskazanego folderu (np. zsynchronizowanego przez Syncthing, Nextcloud albo dysk sieciowy). Zawartość
    pozostaje zaszyfrowana hasłem głównym.
  </p>
  <div class="field">
    <label for="sy-folder">Folder synchronizacji</label>
    <div class="row">
      <input id="sy-folder" type="text" bind:value={folder} onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void setFolder(); } }} placeholder="/ścieżka/do/folderu" class="mono" />
      <button type="button" class="btn" onclick={setFolder} disabled={busy}>{folder.trim() ? 'Ustaw' : 'Wyłącz'}</button>
    </div>
  </div>

  {#if ui.sync?.folder}
    <div class="state" role="status">
      <Icon name={ui.sync.status === 'konflikt' ? 'alert' : ui.sync.status === 'aktualny' ? 'check-circle' : 'sync'} size={20} />
      <span>{ui.sync.error ?? (ui.sync.status ? texts[ui.sync.status] : '')}</span>
    </div>
    {#if canDiff}
      <div class="actions diff-toggle">
        <button type="button" class="btn" disabled={busy} aria-expanded={!!diff} onclick={toggleDiff}>
          <Icon name={diff ? 'eye-off' : 'eye'} /> {diff ? 'Ukryj różnice' : 'Pokaż różnice'}
        </button>
      </div>
    {/if}
    {#if diff && canDiff}
      <section class="diff" aria-label="Różnice między wersją lokalną a plikiem z folderu">
        {#if !diff.readable || !diff.diff}
          <p class="diff-note">
            Plik w folderze ma inne hasło główne (zmieniono je na innym komputerze), więc nie da się go porównać bez tego hasła.
            Różnice zobaczysz dopiero po pobraniu i odblokowaniu nowym hasłem.
          </p>
        {:else if diffIsEmpty(diff.diff)}
          <p class="diff-note">Zawartość jest taka sama po obu stronach; pliki różnią się tylko zapisem.</p>
        {:else}
          <p class="diff-note">{diffIntro(ui.sync.status)}</p>
          {#if groups.length}<p class="diff-note">Różnice: {diffCount(diff.diff)}.</p>{/if}
          <div class="diff-list">
            {#each groups as g (g.side)}
              <h4>{g.title} ({g.rows.length})</h4>
              <ul>
                {#each g.rows as r (r.type + r.id)}
                  <li>
                    <div class="row-head">
                      {#if r.type === 'host'}
                        <span class="badge {r.protocol}">{r.protocol?.toUpperCase()}</span>
                      {:else}
                        <Icon name="folder" size={14} />
                      {/if}
                      <span class="name">{r.name}</span>
                      {#if r.address}<span class="muted mono">{r.address}</span>{/if}
                      <span class="muted where">{r.path || 'najwyższy poziom'}</span>
                    </div>
                    {#if r.changes.length}
                      <ul class="changes">
                        {#each r.changes as c, i (i)}<li>{changeText(c)}</li>{/each}
                      </ul>
                    {/if}
                  </li>
                {/each}
              </ul>
            {/each}
          </div>
          {#each extras as line (line)}<p class="diff-note">{line}</p>{/each}
        {/if}
      </section>
    {/if}
    {#if ui.sync.status === 'konflikt'}
      <div class="actions">
        <button type="button" class="btn" disabled={busy} onclick={() => sync('local')}><Icon name="upload" /> Zachowaj lokalną</button>
        <button type="button" class="btn" disabled={busy} onclick={() => sync('remote')}><Icon name="download" /> Zachowaj zdalną</button>
      </div>
    {:else}
      <div class="actions">
        <button type="button" class="btn primary" disabled={busy || !!ui.sync.error} onclick={() => sync()}><Icon name="sync" /> Synchronizuj teraz</button>
      </div>
    {/if}
  {/if}
  {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}

<style>
  .note { font-size: 12px; margin: 0 0 16px; }
  .row { display: flex; gap: 8px; }
  .state { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--border-strong); border-radius: var(--radius-control); padding: 12px; margin-bottom: 12px; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .diff-toggle { margin-bottom: 12px; }
  .diff { border: 1px solid var(--border); border-radius: var(--radius-control); padding: 12px; margin-bottom: 12px; min-width: 0; }
  .diff-note { font-size: 12px; color: var(--text-muted); margin: 0 0 8px; }
  .diff-note:last-child { margin-bottom: 0; }
  .diff-list { max-height: 260px; overflow-y: auto; margin-bottom: 8px; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); padding: 4px 0; }
  .diff h4 { font-size: 12px; font-weight: 600; margin: 8px 0 4px; }
  .diff ul { list-style: none; margin: 0; padding: 0; }
  .diff-list > ul > li { padding: 4px 0; font-size: 13px; min-width: 0; }
  .row-head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; min-width: 0; }
  .row-head .name { font-weight: 600; overflow-wrap: anywhere; }
  .row-head .mono { font-size: 12px; overflow-wrap: anywhere; }
  .row-head .where { font-size: 12px; margin-left: auto; overflow-wrap: anywhere; }
  .changes { margin: 2px 0 0 22px !important; }
  .changes li { font-size: 12px; color: var(--text-muted); padding: 1px 0; overflow-wrap: anywhere; }
  .changes li::before { content: '- '; }
  .error { margin-top: 12px; font-size: 13px; display: flex; gap: 6px; align-items: center; }
</style>
