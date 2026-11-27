<script lang="ts">
  import { api } from '../api';
  import Icon from '../Icon.svelte';
  import { groupSecret, looksLikeCode } from '../mfa';
  import { notify, refresh, ui } from '../store.svelte';

  const enabled = $derived(ui.doc?.mfa.totp ?? false);
  const recoveryLeft = $derived(ui.doc?.mfa.recovery_left ?? 0);

  // Dane z rozpoczętego włączania: sekret do przepisania i adres do wklejenia w aplikacji.
  let setup = $state<{ secret: string; uri: string } | null>(null);
  // Kody zapasowe pokazywane raz, zaraz po włączeniu.
  let recovery = $state<string[] | null>(null);
  let code = $state('');
  let error = $state('');
  let busy = $state(false);

  async function run(action: () => Promise<void>) {
    busy = true;
    error = '';
    try {
      await action();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  const begin = () => run(async () => {
    recovery = null;
    code = '';
    setup = await api.totpBegin();
  });

  const enable = () => run(async () => {
    recovery = await api.totpEnable(code);
    setup = null;
    code = '';
    await refresh();
    notify('Kody jednorazowe są włączone.');
  });

  const disable = () => run(async () => {
    await api.totpDisable(code);
    code = '';
    recovery = null;
    await refresh();
    notify('Kody jednorazowe są wyłączone.');
  });

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      notify(`Skopiowano ${what}.`);
    } catch {
      notify(`Nie udało się skopiować. Przepisz ${what} ręcznie.`, true);
    }
  }

  /** Enter w polu kodu nie może wysłać formularza całych ustawień. */
  const onEnter = (action: () => void) => (e: KeyboardEvent) => {
    if (e.key === 'Enter') { e.preventDefault(); if (looksLikeCode(code)) action(); }
  };
</script>

<h3 class="section-title">Kody jednorazowe przy otwieraniu pliku (TOTP)</h3>
<p class="form-note">
  Po haśle głównym program pyta jeszcze o kod z aplikacji uwierzytelniającej w telefonie. To zabezpieczenie otwierania pliku
  w programie, a nie część szyfrowania: kto ma plik i zna hasło główne, odszyfruje go innym narzędziem. Wersje programu
  starsze niż ta nie otworzą pliku z włączonymi kodami. Działania w tej sekcji wykonują się od razu.
</p>

{#if recovery}
  <div class="state" role="status">
    <Icon name="alert" size={20} />
    <div>
      <p>Zapisz kody zapasowe teraz. Każdy otwiera plik raz, gdy nie masz telefonu, i nie zobaczysz ich ponownie.</p>
      <ul class="codes mono">{#each recovery as c (c)}<li>{c}</li>{/each}</ul>
      <div class="actions">
        <button type="button" class="btn compact" onclick={() => copy(recovery!.join('\n'), 'kody zapasowe')}><Icon name="copy" size={14} /> Kopiuj kody</button>
        <button type="button" class="btn compact" onclick={() => (recovery = null)}>Zapisałem, schowaj</button>
      </div>
    </div>
  </div>
{/if}

{#if enabled}
  <p class="status"><Icon name="shield-check" size={14} /> Włączone. Kodów zapasowych: {recoveryLeft}.</p>
  <div class="field">
    <label for="mfa-off">Kod z aplikacji albo kod zapasowy, żeby wyłączyć</label>
    <div class="row">
      <input id="mfa-off" type="text" class="mono" inputmode="numeric" autocomplete="off" bind:value={code} onkeydown={onEnter(disable)} />
      <button type="button" class="btn" disabled={busy || !looksLikeCode(code)} onclick={disable}>Wyłącz</button>
    </div>
  </div>
{:else if setup}
  <div class="field">
    <span class="label">1. Dodaj konto w aplikacji uwierzytelniającej, wpisując ten sekret (typ: oparty na czasie)</span>
    <div class="row">
      <span class="secret mono">{groupSecret(setup.secret)}</span>
      <button type="button" class="btn compact" onclick={() => copy(setup!.secret, 'sekret')}><Icon name="copy" size={14} /> Kopiuj</button>
    </div>
    <span class="hint muted">Zamiast sekretu możesz wkleić w aplikacji adres konfiguracji.</span>
    <div class="actions">
      <button type="button" class="btn compact" onclick={() => copy(setup!.uri, 'adres konfiguracji')}><Icon name="link" size={14} /> Kopiuj adres konfiguracji</button>
    </div>
  </div>
  <div class="field">
    <label for="mfa-on">2. Wpisz kod, który pokazuje aplikacja</label>
    <div class="row">
      <input id="mfa-on" type="text" class="mono" inputmode="numeric" autocomplete="off" bind:value={code} onkeydown={onEnter(enable)} />
      <button type="button" class="btn primary" disabled={busy || !looksLikeCode(code)} onclick={enable}>Potwierdź i włącz</button>
      <button type="button" class="btn" disabled={busy} onclick={() => { setup = null; code = ''; error = ''; }}>Anuluj</button>
    </div>
  </div>
{:else}
  <div class="actions">
    <button type="button" class="btn" disabled={busy} onclick={begin}><Icon name="shield" size={14} /> Włącz kody jednorazowe</button>
  </div>
{/if}
{#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> <span>{error}</span></div>{/if}

<style>
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .row input { flex: 1; min-width: 120px; }
  .label { font-size: 13px; }
  .secret { font-size: 14px; letter-spacing: 0.04em; user-select: text; overflow-wrap: anywhere; border: 1px solid var(--border); border-radius: var(--radius-control); padding: 6px 10px; }
  .status { display: flex; gap: 6px; align-items: center; font-size: 13px; margin: 0 0 12px; }
  .state { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--border-strong); border-radius: var(--radius-control); padding: 12px; margin-bottom: 14px; font-size: 13px; }
  .state p { margin: 0 0 8px; }
  .codes { list-style: none; margin: 0 0 10px; padding: 0; display: grid; grid-template-columns: repeat(2, max-content); gap: 4px 24px; user-select: text; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
  .error { margin-top: 12px; font-size: 13px; display: flex; gap: 6px; align-items: flex-start; overflow-wrap: anywhere; }
</style>
