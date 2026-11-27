<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type Id, type LocalConfig, type Settings } from './api';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import Tabs, { type TabItem } from './Tabs.svelte';
  import BackupsDialog from './BackupsDialog.svelte';
  import DiagnosticsDialog from './DiagnosticsDialog.svelte';
  import AboutDialog from './AboutDialog.svelte';
  import SyncPanel from './settings/SyncPanel.svelte';
  import ShortcutsPanel from './settings/ShortcutsPanel.svelte';
  import TransferPanel from './settings/TransferPanel.svelte';
  import MfaPanel from './settings/MfaPanel.svelte';
  import { CATEGORIES, type SettingsCategory } from './settings/categories';
  import { SCHEMES } from './terminalThemes';
  import { binding } from './shortcuts';
  import { applyTheme, notify, refresh, ui } from './store.svelte';
  import { backupCountError, passwordChangeError, settingsError } from './validation';

  let { onclose, initial = 'appearance', exportFolder = null }: {
    onclose: () => void;
    initial?: SettingsCategory;
    /** Katalog podpowiedziany jako zakres eksportu (z menu drzewa hostów). */
    exportFolder?: Id | null;
  } = $props();
  // svelte-ignore state_referenced_locally
  let settings = $state<Settings>(structuredClone($state.snapshot(ui.doc!.settings)));
  // svelte-ignore state_referenced_locally
  let selected = $state<string>(initial);
  let local = $state<LocalConfig | null>(null);
  let oldPw = $state('');
  let newPw = $state('');
  let newPw2 = $state('');
  let error = $state('');
  let invalid = $state<SettingsCategory | null>(null);
  let busy = $state(false);
  let tool = $state<'backups' | 'diagnostics' | 'about' | null>(null);
  // Wartości konfiguracji lokalnej z chwili wczytania, żeby zapisywać tylko zmienione przełączniki.
  let localLoaded: LocalConfig | null = null;

  const items = $derived<TabItem[]>(CATEGORIES.map((c) => ({ ...c, invalid: c.id === invalid })));

  onMount(() => {
    api.getLocalConfig().then((c) => {
      local = c;
      localLoaded = { ...c };
    }).catch(() => {});
  });

  function fail(category: SettingsCategory, message: string) {
    error = message;
    invalid = category;
    selected = category;
  }

  async function save(e: Event) {
    e.preventDefault();
    error = '';
    invalid = null;
    const bad = settingsError(settings);
    if (bad) return fail(bad.category, bad.message);
    if (local) {
      const b = backupCountError(local.backup_count);
      if (b) return fail('security', b);
    }
    const pw = passwordChangeError(oldPw, newPw, newPw2);
    if (pw) return fail('security', pw);
    busy = true;
    try {
      // Zmiana hasła idzie pierwsza: złe obecne hasło wykrywa dopiero backend, a wtedy nic innego
      // nie może być już zapisane. Pola są czyszczone, żeby ponowny zapis nie zmieniał hasła drugi raz.
      if (oldPw || newPw || newPw2) {
        await api.changePassword(oldPw, newPw);
        oldPw = newPw = newPw2 = '';
        notify('Hasło główne zostało zmienione.');
      }
      await api.saveSettings($state.snapshot(settings));
      if (local && localLoaded) {
        if (local.log_sessions !== localLoaded.log_sessions) await api.setLogSessions(local.log_sessions);
        if (local.rdp_clipboard !== localLoaded.rdp_clipboard) await api.setRdpClipboard(local.rdp_clipboard);
        if (local.backup_count !== localLoaded.backup_count) await api.setBackupCount(local.backup_count);
        if (local.check_updates !== localLoaded.check_updates) await api.setCheckUpdates(local.check_updates);
      }
      await refresh();
      applyTheme(settings);
      notify('Zapisano ustawienia.');
      onclose();
    } catch (err) {
      error = String(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Ustawienia" {onclose} width={760} height={600} flush>
  <form id="settings-form" class="form-fill" novalidate onsubmit={save}>
    <Tabs orientation="vertical" label="Kategorie ustawień" idPrefix="settings" {items} bind:selected {panel} />
  </form>
  {#snippet footer()}
    {#if error}<div class="form-error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
    <button class="btn" type="button" onclick={onclose}>Anuluj</button>
    <button class="btn primary" type="submit" form="settings-form" disabled={busy}>Zapisz</button>
  {/snippet}
</Modal>

{#if tool === 'backups'}
  <BackupsDialog onclose={() => (tool = null)} onrestored={onclose} />
{:else if tool === 'diagnostics'}
  <DiagnosticsDialog onclose={() => (tool = null)} />
{:else if tool === 'about'}
  <AboutDialog onclose={() => (tool = null)} />
{/if}

{#snippet panel(id: string)}
  {#if id === 'appearance'}
    <div class="field">
      <label for="s-theme">Motyw</label>
      <select id="s-theme" bind:value={settings.theme}>
        <option value="system">Zgodnie z systemem</option>
        <option value="dark">Ciemny</option>
        <option value="light">Jasny</option>
      </select>
    </div>
  {:else if id === 'terminal'}
    <div class="field">
      <label for="s-tfont">Krój czcionki</label>
      <select id="s-tfont" bind:value={settings.terminal_font}>
        <option value="bundled">JetBrains Mono (wbudowana)</option>
        <option value="system">Systemowa o stałej szerokości</option>
      </select>
    </div>
    <div class="two">
      <div class="field">
        <label for="s-font">Rozmiar czcionki (px)</label>
        <input id="s-font" type="number" min="9" max="32" bind:value={settings.terminal_font_size} />
      </div>
      <div class="field">
        <label for="s-scheme">Schemat</label>
        <select id="s-scheme" bind:value={settings.terminal_scheme}>
          {#each Object.entries(SCHEMES) as [sid, name] (sid)}<option value={sid}>{name}</option>{/each}
        </select>
      </div>
    </div>
    <div class="field">
      <label for="s-cursor">Kształt kursora</label>
      <select id="s-cursor" bind:value={settings.terminal_cursor}>
        <option value="block">Blok</option>
        <option value="bar">Kreska</option>
        <option value="underline">Podkreślenie</option>
      </select>
    </div>
    <label class="check"><input type="checkbox" bind:checked={settings.terminal_cursor_blink} /><span>Migający kursor</span></label>
    <div class="field">
      <label for="s-scroll">Historia przewijania (wiersze)</label>
      <input id="s-scroll" type="number" min="0" max="100000" bind:value={settings.terminal_scrollback} />
      <span class="hint muted">Każda karta trzyma tyle wierszy w pamięci.</span>
    </div>
    <label class="check"><input type="checkbox" bind:checked={settings.terminal_copy_on_select} /><span>Kopiuj zaznaczony tekst do schowka</span></label>
    <label class="check">
      <input type="checkbox" bind:checked={settings.terminal_paste_right_click} />
      <span>Wklejaj prawym przyciskiem myszy <span class="muted">(zamiast menu kontekstowego)</span></span>
    </label>
    <div class="field">
      <label for="s-term">Domyślny typ terminala (TERM)</label>
      <input id="s-term" type="text" class="mono" list="s-term-list" bind:value={settings.ssh_term} autocomplete="off" maxlength="64" placeholder="xterm-256color" />
      <datalist id="s-term-list">
        <option value="xterm-256color"></option>
        <option value="xterm"></option>
        <option value="vt220"></option>
        <option value="vt100"></option>
        <option value="aixterm"></option>
        <option value="ansi"></option>
      </datalist>
      <span class="hint muted">Używany, gdy host ani katalog nie ustawia własnego. Dotyczy nowych połączeń.</span>
    </div>
    <p class="form-note">Zmiany wyglądu terminala działają także w otwartych kartach. Rozmiar czcionki i schemat można też ustawić dla katalogu lub hosta.</p>
  {:else if id === 'rdp'}
    <div class="field">
      <label for="s-profile">Łącze RDP</label>
      <select id="s-profile" bind:value={settings.rdp_profile}>
        <option value="fast">Szybkie</option>
        <option value="slow">Wolne</option>
      </select>
      <span class="hint muted">Wolne wyłącza efekty pulpitu (tapetę, animacje, motywy) i wygładzanie czcionek, żeby serwer wysyłał mniej zmian obrazu. Profil można zmienić dla katalogu lub hosta.</span>
    </div>
    <div class="field">
      <label for="s-keys">Przechwytywanie klawiszy w sesji RDP</label>
      <select id="s-keys" bind:value={settings.rdp_keys}>
        <option value="never">Nigdy</option>
        <option value="fullscreen">Tylko na pełnym ekranie</option>
        <option value="always">Zawsze, gdy sesja ma fokus</option>
      </select>
      <span class="hint muted">Przechwycone klawisze, także skróty aplikacji, trafiają do zdalnego pulpitu. Skrót zwalniający: {binding(settings, 'release_keys')}.</span>
    </div>
    {#if local}
      <label class="check">
        <input type="checkbox" bind:checked={local.rdp_clipboard} />
        <span>Udostępniaj schowek sesjom RDP <span class="muted">(tekst, HTML, obrazy i pliki, w obie strony)</span></span>
      </label>
    {/if}
  {:else if id === 'sessions'}
    <label class="check"><input type="checkbox" bind:checked={settings.confirm_close_tab} /><span>Pytaj przed zamknięciem karty z połączoną sesją</span></label>
    <label class="check"><input type="checkbox" bind:checked={settings.confirm_quit} /><span>Pytaj przed zamknięciem programu, gdy są otwarte sesje</span></label>
    <div class="field">
      <label for="s-ka">Podtrzymywanie połączenia SSH (sekundy)</label>
      <input id="s-ka" type="number" min="0" max="3600" bind:value={settings.ssh_keepalive_secs} />
      <span class="hint muted">Co tyle sekund program wysyła serwerowi pusty komunikat, żeby zapora albo serwer nie zamknęły bezczynnego połączenia. 0 wyłącza. Dotyczy nowych połączeń.</span>
    </div>
    {#if local}
      <label class="check">
        <input type="checkbox" bind:checked={local.log_sessions} />
        <span>Zapisuj wyjście sesji SSH do plików <span class="muted">(dziennik sesji, tylko ta maszyna)</span></span>
      </label>
      <p class="form-note mono">{local.logs_dir}</p>
    {/if}
  {:else if id === 'security'}
    <div class="field">
      <label for="s-lock">Automatyczna blokada po bezczynności (minuty)</label>
      <input id="s-lock" type="number" min="0" max="1440" bind:value={settings.auto_lock_minutes} />
      <span class="hint muted">Gdy przez tyle minut nie używasz klawiatury ani myszy w oknie programu (także w sesjach), plik z hostami zostaje zablokowany, a sesje rozłączone. 0 wyłącza.</span>
    </div>
    {#if local}
      <div class="field">
        <label for="s-bak">Liczba kopii zapasowych</label>
        <input id="s-bak" type="number" min="1" max="20" bind:value={local.backup_count} />
        <span class="hint muted">Kopie poprzednich wersji pliku z hostami na tej maszynie. Zmniejszenie liczby usuwa starsze kopie ponad limit.</span>
      </div>
    {/if}
    <h3 class="section-title">Zmiana hasła głównego</h3>
    <div class="field"><label for="s-old">Obecne hasło</label><input id="s-old" type="password" bind:value={oldPw} autocomplete="off" /></div>
    <div class="field"><label for="s-new">Nowe hasło</label><input id="s-new" type="password" bind:value={newPw} autocomplete="off" /></div>
    <div class="field"><label for="s-new2">Powtórz nowe hasło</label><input id="s-new2" type="password" bind:value={newPw2} autocomplete="off" /></div>
    <p class="form-note">Zaufane klucze i certyfikaty: {ui.doc?.trusted_count ?? 0}.</p>
    <MfaPanel />
  {:else if id === 'sync'}
    <SyncPanel {onclose} />
  {:else if id === 'transfer'}
    <TransferPanel folder={exportFolder} />
  {:else if id === 'shortcuts'}
    <ShortcutsPanel bind:settings />
  {:else if id === 'tools'}
    <div class="tools">
      <button type="button" class="btn compact" onclick={() => (tool = 'backups')}><Icon name="clock" size={14} /> Kopie zapasowe</button>
      <button type="button" class="btn compact" onclick={() => (tool = 'diagnostics')}><Icon name="file-text" size={14} /> Dziennik diagnostyczny</button>
      <button type="button" class="btn compact" onclick={() => (tool = 'about')}><Icon name="info" size={14} /> O programie</button>
    </div>
    {#if local}
      <label class="check updates">
        <input type="checkbox" bind:checked={local.check_updates} />
        <span>Sprawdzaj po uruchomieniu, czy jest nowa wersja <span class="muted">(program łączy się wtedy z api.github.com; tylko ta maszyna)</span></span>
      </label>
      <p class="form-note">Program tylko informuje o nowym wydaniu i niczego sam nie pobiera. Zmiana obowiązuje po zapisaniu ustawień.</p>
    {/if}
  {/if}
{/snippet}

<style>
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .tools { display: flex; flex-wrap: wrap; gap: 8px; }
  .updates { margin-top: 20px; }
  .section-title { margin-top: 8px; }
  @media (max-width: 700px) { .two { grid-template-columns: 1fr; } }
</style>
