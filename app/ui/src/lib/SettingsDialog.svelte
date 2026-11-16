<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type LocalConfig, type Settings } from './api';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import { SCHEMES } from './terminalThemes';
  import { binding } from './shortcuts';
  import { applyTheme, notify, refresh, ui } from './store.svelte';
  import { fontSizeError, passwordChangeError } from './validation';

  let { onclose, onopen }: { onclose: () => void; onopen: (tool: 'backups' | 'shortcuts' | 'diagnostics' | 'about') => void } = $props();
  // svelte-ignore state_referenced_locally
  let settings = $state<Settings>(structuredClone($state.snapshot(ui.doc!.settings)));
  let local = $state<LocalConfig | null>(null);
  let oldPw = $state('');
  let newPw = $state('');
  let newPw2 = $state('');
  let error = $state('');
  let busy = $state(false);
  // Wartości konfiguracji lokalnej z chwili wczytania, żeby zapisywać tylko zmienione przełączniki.
  let localLoaded: LocalConfig | null = null;

  onMount(() => {
    api.getLocalConfig().then((c) => {
      local = c;
      localLoaded = { ...c };
    }).catch(() => {});
  });

  async function save(e: Event) {
    e.preventDefault();
    const problem = fontSizeError(settings.terminal_font_size) ?? passwordChangeError(oldPw, newPw, newPw2);
    if (problem) {
      error = problem;
      return;
    }
    error = '';
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
      }
      await refresh();
      applyTheme(settings);
      onclose();
    } catch (err) {
      error = String(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Ustawienia" {onclose} width={520}>
  <form id="settings-form" onsubmit={save}>
    <div class="field">
      <label for="s-theme">Motyw</label>
      <select id="s-theme" bind:value={settings.theme}>
        <option value="system">Zgodnie z systemem</option>
        <option value="dark">Ciemny</option>
        <option value="light">Jasny</option>
      </select>
    </div>
    <div class="two">
      <div class="field">
        <label for="s-font">Czcionka terminala (px)</label>
        <input id="s-font" type="number" min="9" max="32" bind:value={settings.terminal_font_size} />
      </div>
      <div class="field">
        <label for="s-scheme">Schemat terminala</label>
        <select id="s-scheme" bind:value={settings.terminal_scheme}>
          {#each Object.entries(SCHEMES) as [id, name] (id)}<option value={id}>{name}</option>{/each}
        </select>
      </div>
    </div>
    <p class="muted info">Zmiany terminala dotyczą nowych kart. Schemat można też ustawić dla katalogu lub hosta.</p>

    <div class="field rdp">
      <label for="s-profile">Łącze RDP</label>
      <select id="s-profile" bind:value={settings.rdp_profile}>
        <option value="fast">Szybkie</option>
        <option value="slow">Wolne</option>
      </select>
      <span class="hint muted">Wolne wyłącza efekty pulpitu (tapetę, animacje, motywy), żeby serwer wysyłał mniej zmian obrazu. Profil można zmienić dla katalogu lub hosta.</span>
    </div>
    <div class="field">
      <label for="s-keys">Przechwytywanie klawiszy w sesji RDP</label>
      <select id="s-keys" bind:value={settings.rdp_keys}>
        <option value="never">Nigdy</option>
        <option value="fullscreen">Tylko na pełnym ekranie</option>
        <option value="always">Zawsze, gdy sesja ma fokus</option>
      </select>
      <span class="hint muted">Przechwycone klawisze, także skróty aplikacji, trafiają do zdalnego pulpitu. Skrót zwalniający: {binding(ui.doc?.settings, 'release_keys')}.</span>
    </div>

    {#if local}
      <label class="check">
        <input type="checkbox" bind:checked={local.rdp_clipboard} />
        <span>Udostępniaj schowek sesjom RDP <span class="muted">(tekst, HTML, obrazy i pliki, w obie strony)</span></span>
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={local.log_sessions} />
        <span>Zapisuj wyjście sesji SSH do plików <span class="muted">(dziennik sesji, tylko ta maszyna)</span></span>
      </label>
      <p class="muted info mono">{local.logs_dir}</p>
    {/if}

    <h3>Zmiana hasła głównego</h3>
    <div class="field"><label for="s-old">Obecne hasło</label><input id="s-old" type="password" bind:value={oldPw} autocomplete="off" /></div>
    <div class="field"><label for="s-new">Nowe hasło</label><input id="s-new" type="password" bind:value={newPw} autocomplete="off" /></div>
    <div class="field"><label for="s-new2">Powtórz nowe hasło</label><input id="s-new2" type="password" bind:value={newPw2} autocomplete="off" /></div>

    <h3>Narzędzia</h3>
    <div class="tools">
      <button type="button" class="btn compact" onclick={() => onopen('backups')}><Icon name="clock" size={14} /> Kopie zapasowe</button>
      <button type="button" class="btn compact" onclick={() => onopen('shortcuts')}><Icon name="keyboard" size={14} /> Skróty klawiszowe</button>
      <button type="button" class="btn compact" onclick={() => onopen('diagnostics')}><Icon name="file-text" size={14} /> Dziennik diagnostyczny</button>
      <button type="button" class="btn compact" onclick={() => onopen('about')}><Icon name="info" size={14} /> O programie</button>
    </div>
    <p class="muted info">Zaufane klucze i certyfikaty: {ui.doc?.trusted_count ?? 0}.</p>
    {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
  </form>
  {#snippet footer()}
    <button class="btn" type="button" onclick={onclose}>Anuluj</button>
    <button class="btn primary" type="submit" form="settings-form" disabled={busy}>Zapisz</button>
  {/snippet}
</Modal>

<style>
  h3 { font-size: 14px; margin: 20px 0 12px; font-weight: 600; }
  .info { font-size: 12px; margin: 4px 0 0; overflow-wrap: anywhere; }
  .rdp { margin-top: 14px; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .check { display: flex; gap: 10px; align-items: flex-start; margin-top: 14px; font-size: 13px; }
  .check input { margin-top: 2px; }
  .tools { display: flex; flex-wrap: wrap; gap: 8px; }
  .error { margin-top: 12px; font-size: 13px; display: flex; gap: 6px; align-items: center; }
</style>
