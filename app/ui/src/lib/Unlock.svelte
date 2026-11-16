<script lang="ts">
  import { api } from './api';
  import { afterUnlock, ui } from './store.svelte';
  import Icon from './Icon.svelte';

  const creating = $derived(ui.phase === 'missing');
  let password = $state('');
  let repeat = $state('');
  let error = $state('');
  let busy = $state(false);
  let show = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    error = '';
    if (creating && password !== repeat) {
      error = 'Hasła nie są takie same.';
      return;
    }
    busy = true;
    try {
      await (creating ? api.createVault(password) : api.unlock(password));
      password = repeat = '';
      await afterUnlock();
    } catch (err) {
      error = String(err);
    } finally {
      busy = false;
    }
  }
</script>

<main>
  <form onsubmit={submit}>
    <div class="logo"><Icon name={creating ? 'shield-check' : 'lock'} size={28} /></div>
    <h1>{creating ? 'Pierwsze uruchomienie' : 'Odblokuj hasłem głównym'}</h1>
    <p class="muted">
      {creating
        ? 'Hosty i hasła będą zapisane w pliku zaszyfrowanym hasłem głównym. Nie da się go odzyskać bez tego hasła.'
        : 'Plik z hostami jest zaszyfrowany.'}
    </p>
    <div class="field">
      <label for="pw">Hasło główne</label>
      <div class="row">
        <input id="pw" type={show ? 'text' : 'password'} bind:value={password} class:invalid={!!error} autocomplete="off" />
        <button type="button" class="icon-btn" aria-label={show ? 'Ukryj hasło' : 'Pokaż hasło'} onclick={() => (show = !show)}>
          <Icon name={show ? 'eye-off' : 'eye'} />
        </button>
      </div>
    </div>
    {#if creating}
      <div class="field">
        <label for="pw2">Powtórz hasło</label>
        <input id="pw2" type={show ? 'text' : 'password'} bind:value={repeat} autocomplete="off" />
        <span class="hint">Co najmniej 8 znaków.</span>
      </div>
    {/if}
    {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
    <button class="btn primary" disabled={busy || !password}>
      <Icon name={creating ? 'plus' : 'unlock'} />
      {busy ? 'Pracuję...' : creating ? 'Utwórz plik' : 'Odblokuj'}
    </button>
  </form>
</main>

<style>
  main { height: 100%; display: grid; place-items: center; padding: 16px; }
  form { width: min(420px, 100%); background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius-window); padding: 32px; display: flex; flex-direction: column; }
  .logo { width: 56px; height: 56px; display: grid; place-items: center; border: 1px solid var(--border-strong); border-radius: var(--radius-menu); margin-bottom: 16px; }
  h1 { font-size: 20px; margin: 0 0 8px; font-weight: 600; }
  p { margin: 0 0 20px; font-size: 13px; }
  .row { display: flex; gap: 8px; align-items: center; }
  /* overflow-wrap: komunikat może zawierać długą ścieżkę pliku bez spacji. */
  .error { font-size: 13px; margin-bottom: 14px; display: flex; gap: 6px; align-items: center; overflow-wrap: anywhere; border: 1px solid var(--text); border-radius: var(--radius-control); padding: 8px 10px; }
</style>
