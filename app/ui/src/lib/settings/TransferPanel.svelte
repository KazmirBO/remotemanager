<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type Id } from '../api';
  import Icon from '../Icon.svelte';
  import { notify, refresh, ui } from '../store.svelte';
  import {
    MAX_IMPORT_FILE, PARTS, defaultParts, exportPasswordError, exportText, folderChoices, importFormat, reportText, summaryText,
    type ImportFormat, type ImportSummary, type Parts,
  } from '../transfer';

  /** Katalog wybrany z menu drzewa hostów; bez niego eksport obejmuje całą listę. */
  let { folder = null }: { folder?: Id | null } = $props();

  // ---------- eksport ----------
  // svelte-ignore state_referenced_locally
  let scope = $state<string>(folder ?? '');
  let exportParts = $state<Parts>(defaultParts());
  let exportPw = $state('');
  let exportPw2 = $state('');
  let path = $state('');
  let exportError = $state('');
  let exportDone = $state('');
  let exporting = $state(false);

  const choices = $derived(folderChoices(ui.doc?.folders ?? []));
  const leaksSecrets = $derived(exportParts.passwords || exportParts.ssh_keys);

  onMount(() => {
    api.exportDefaultPath().then((p) => { if (!path) path = p; }).catch(() => {});
  });

  async function doExport() {
    exportError = '';
    exportDone = '';
    const bad = exportPasswordError(exportPw, exportPw2);
    if (bad) { exportError = bad; return; }
    if (!path.trim()) { exportError = 'Podaj ścieżkę pliku eksportu.'; return; }
    exporting = true;
    try {
      const done = await api.exportHosts(path, exportPw, $state.snapshot(exportParts), scope || null);
      exportDone = `${exportText(done)} Plik: ${done.path}`;
      exportPw = exportPw2 = '';
      notify('Eksport zakończony.');
    } catch (e) {
      exportError = String(e);
    } finally {
      exporting = false;
    }
  }

  // ---------- import ----------
  let picker = $state<HTMLInputElement>();
  let fileName = $state('');
  // Zaszyfrowane bajty pliku; treść odszyfrowuje wyłącznie backend.
  let fileData: Uint8Array | null = null;
  let hasFile = $state(false);
  // Lista CSV jest jawna i nie ma hasła; plik eksportu wymaga hasła pliku.
  let format = $state<ImportFormat>('mrmx');
  let importPw = $state('');
  let summary = $state<ImportSummary | null>(null);
  let importParts = $state<Parts>(defaultParts());
  let existing = $state<'skip' | 'update'>('skip');
  let importError = $state('');
  let importDone = $state('');
  let importing = $state(false);

  const existingCount = $derived(summary ? summary.hosts_existing + summary.folders_existing : 0);
  const available = $derived(summary ? PARTS.filter((p) => summary!.parts[p.id]) : []);
  const needsTrust = $derived(available.some((p) => p.trust));

  async function pick(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    importError = '';
    importDone = '';
    summary = null;
    fileData = null;
    hasFile = false;
    fileName = file.name;
    format = importFormat(file.name);
    importPw = '';
    if (file.size > MAX_IMPORT_FILE) {
      importError = 'Plik jest za duży na plik importu hostów (limit 4 MiB).';
      return;
    }
    try {
      fileData = new Uint8Array(await file.arrayBuffer());
      hasFile = true;
    } catch (err) {
      importError = `Nie można odczytać pliku: ${err}`;
    }
  }

  async function check() {
    if (!fileData || (format === 'mrmx' && !importPw)) return;
    importError = '';
    importDone = '';
    summary = null;
    importing = true;
    try {
      const s = await api.importPreview(fileData, importPw, format);
      importParts = defaultParts(s.parts);
      existing = 'skip';
      summary = s;
    } catch (e) {
      importError = String(e);
    } finally {
      importing = false;
    }
  }

  async function doImport() {
    if (!fileData || !summary) return;
    importError = '';
    importing = true;
    try {
      const report = await api.importHosts(fileData, importPw, format, $state.snapshot(importParts), existing);
      importDone = reportText(report);
      summary = null;
      fileData = null;
      hasFile = false;
      fileName = '';
      importPw = '';
      await refresh();
      notify('Import zakończony.');
    } catch (e) {
      importError = String(e);
    } finally {
      importing = false;
    }
  }

  /** Enter w polu nie może wysłać formularza całych ustawień. */
  const onEnter = (action: () => void) => (e: KeyboardEvent) => {
    if (e.key === 'Enter') { e.preventDefault(); action(); }
  };
</script>

<p class="form-note">Działania w tej kategorii wykonują się od razu, przycisk Zapisz ich nie dotyczy.</p>
<p class="muted note">
  Eksport zapisuje hosty i katalogi do osobnego pliku zaszyfrowanego hasłem, które podajesz niżej. Wybierasz, które dane trafiają do pliku,
  a przy imporcie, które z niego bierzesz. Ustawienia programu nie są przenoszone.
</p>

<h3 class="section-title first">Eksport</h3>
<div class="field">
  <label for="tr-scope">Zakres</label>
  <select id="tr-scope" bind:value={scope}>
    <option value="">Cała lista hostów</option>
    {#each choices as c (c.id)}<option value={c.id}>Katalog: {c.label}</option>{/each}
  </select>
</div>
<fieldset class="parts">
  <legend>Dane w pliku (nazwy, adresy i struktura katalogów są zawsze)</legend>
  {#each PARTS as p (p.id)}
    <label class="check"><input type="checkbox" bind:checked={exportParts[p.id]} /><span>{p.label}</span></label>
  {/each}
</fieldset>
{#if leaksSecrets}
  <div class="state" role="status">
    <Icon name="alert" size={20} />
    <span>Plik będzie zawierał hasła albo klucze prywatne. Chroni je tylko hasło pliku: kto je pozna, odczyta wszystko.</span>
  </div>
{/if}
<div class="two">
  <div class="field">
    <label for="tr-pw">Hasło pliku</label>
    <input id="tr-pw" type="password" bind:value={exportPw} autocomplete="new-password" onkeydown={onEnter(doExport)} />
  </div>
  <div class="field">
    <label for="tr-pw2">Powtórz hasło pliku</label>
    <input id="tr-pw2" type="password" bind:value={exportPw2} autocomplete="new-password" onkeydown={onEnter(doExport)} />
  </div>
</div>
<div class="field">
  <label for="tr-path">Plik eksportu</label>
  <input id="tr-path" type="text" class="mono" bind:value={path} placeholder="/ścieżka/do/pliku.mrmx" onkeydown={onEnter(doExport)} />
  <span class="hint muted">Pełna ścieżka nowego pliku. Istniejący plik nie zostanie nadpisany, a rozszerzenie .mrmx jest dopisywane.</span>
</div>
<div class="actions">
  <button type="button" class="btn primary" disabled={exporting} onclick={doExport}><Icon name="upload" /> Eksportuj</button>
</div>
{#if exportDone}<div class="result" role="status"><Icon name="check-circle" size={14} /> <span>{exportDone}</span></div>{/if}
{#if exportError}<div class="error" role="alert"><Icon name="alert" size={14} /> <span>{exportError}</span></div>{/if}

<h3 class="section-title">Import</h3>
<div class="field">
  <label for="tr-file">Plik eksportu albo lista CSV</label>
  <div class="row">
    <button id="tr-file" type="button" class="btn" disabled={importing} onclick={() => picker?.click()}>Wybierz plik...</button>
    <span class="file mono" class:muted={!fileName}>{fileName || 'nie wybrano pliku'}</span>
  </div>
  <input bind:this={picker} type="file" accept=".mrmx,.csv" hidden onchange={pick} />
  <span class="hint muted">Plik .mrmx z eksportu albo lista hostów w .csv z kolumnami: nazwa, adres, protokol (ssh albo rdp), katalog.</span>
</div>
{#if hasFile && format === 'csv'}
  <div class="actions csv-check">
    <button type="button" class="btn" disabled={importing} onclick={check}>Sprawdź plik</button>
  </div>
{:else if hasFile}
  <div class="field">
    <label for="tr-ipw">Hasło pliku</label>
    <div class="row">
      <input id="tr-ipw" type="password" bind:value={importPw} autocomplete="off" onkeydown={onEnter(check)} />
      <button type="button" class="btn" disabled={importing || !importPw} onclick={check}>Sprawdź plik</button>
    </div>
  </div>
{/if}
{#if summary}
  <div class="state" role="status">
    <Icon name="info" size={20} />
    <span>{summaryText(summary)}</span>
  </div>
  {#if available.length}
    <fieldset class="parts">
      <legend>Dane do zaimportowania (nazwy, adresy i struktura katalogów są zawsze)</legend>
      {#each available as p (p.id)}
        <label class="check"><input type="checkbox" bind:checked={importParts[p.id]} /><span>{p.label}</span></label>
      {/each}
      {#if needsTrust}
        <p class="form-note">
          Polecenie po zalogowaniu i zaufane klucze bierz tylko z pliku od osoby, której ufasz: polecenie wykona się na serwerze po
          połączeniu, a zaufany klucz wyłącza pytanie o klucz hosta przy pierwszym połączeniu.
        </p>
      {/if}
    </fieldset>
  {:else}
    <p class="form-note">Plik zawiera tylko nazwy, adresy i strukturę katalogów.</p>
  {/if}
  {#if existingCount}
    <fieldset class="parts">
      <legend>Hosty i katalogi, które już masz ({existingCount})</legend>
      <label class="check"><input type="radio" name="tr-existing" value="skip" bind:group={existing} /><span>Pomiń (zostają bez zmian)</span></label>
      <label class="check">
        <input type="radio" name="tr-existing" value="update" bind:group={existing} />
        <span>Zaktualizuj: nazwa, adres, protokół i położenie z pliku oraz zaznaczone wyżej dane. Niezaznaczone dane i ulubione zostają Twoje.</span>
      </label>
    </fieldset>
  {/if}
  <div class="actions">
    <button type="button" class="btn primary" disabled={importing} onclick={doImport}><Icon name="download" /> Importuj</button>
  </div>
{/if}
{#if importDone}<div class="result" role="status"><Icon name="check-circle" size={14} /> <span>{importDone}</span></div>{/if}
{#if importError}<div class="error" role="alert"><Icon name="alert" size={14} /> <span>{importError}</span></div>{/if}

<style>
  .note { font-size: 12px; margin: 0 0 16px; }
  .section-title.first { margin-top: 0; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .row { display: flex; gap: 8px; align-items: center; }
  .row input { flex: 1; min-width: 0; }
  .file { font-size: 12px; min-width: 0; overflow-wrap: anywhere; }
  .parts { border: 1px solid var(--border); border-radius: var(--radius-control); margin: 0 0 14px; padding: 10px 12px 0; min-width: 0; }
  .parts legend { font-size: 12px; color: var(--text-muted); padding: 0 4px; }
  .parts .check { margin-bottom: 10px; }
  .state { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--border-strong); border-radius: var(--radius-control); padding: 12px; margin-bottom: 14px; font-size: 13px; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .csv-check { margin-bottom: 14px; }
  .result, .error { margin-top: 12px; font-size: 13px; display: flex; gap: 6px; align-items: flex-start; overflow-wrap: anywhere; }
  .result :global(svg), .error :global(svg) { flex: none; margin-top: 2px; }
  @media (max-width: 700px) { .two { grid-template-columns: 1fr; } }
</style>
