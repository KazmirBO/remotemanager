<script lang="ts">
  import { api } from './api';
  import { afterUnlock, ui } from './store.svelte';
  import Icon from './Icon.svelte';
  import { looksLikeCode, unlockStep } from './mfa';

  const creating = $derived(ui.phase === 'missing');
  let password = $state('');
  let repeat = $state('');
  let error = $state('');
  let busy = $state(false);
  let show = $state(false);
  // Drugi krok: plik wymaga kodu z aplikacji uwierzytelniającej. Hasło zostało już przyjęte.
  let needCode = $state(false);
  let code = $state('');
  let codeInput = $state<HTMLInputElement>();

  $effect(() => {
    if (needCode) codeInput?.focus();
  });

  async function submit(e: Event) {
    e.preventDefault();
    error = '';
    if (needCode) return submitCode();
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
      const step = unlockStep(err);
      if (step.kind === 'needs_code') {
        // Hasło było dobre: nie trzymamy go dłużej w polu.
        password = '';
        code = '';
        needCode = true;
      } else {
        error = step.message;
      }
    } finally {
      busy = false;
    }
  }

  async function submitCode() {
    busy = true;
    try {
      await api.unlockTotp(code);
      code = '';
      needCode = false;
      await afterUnlock();
    } catch (err) {
      const step = unlockStep(err);
      error = step.message;
      code = '';
      // Za dużo prób albo minął czas: odblokowanie zaczyna się od hasła.
      if (step.kind !== 'bad_code') needCode = false;
    } finally {
      busy = false;
    }
  }

  function backToPassword() {
    needCode = false;
    code = '';
    error = '';
  }
</script>

<main>
  <form onsubmit={submit}>
    <div class="logo"><Icon name={creating ? 'shield-check' : needCode ? 'shield' : 'lock'} size={28} /></div>
    <h1>{creating ? 'Pierwsze uruchomienie' : needCode ? 'Podaj kod jednorazowy' : 'Odblokuj hasłem głównym'}</h1>
    <p class="muted">
      {creating
        ? 'Hosty, hasła i klucze będą zapisane w pliku zaszyfrowanym hasłem głównym. Nie da się go odzyskać bez tego hasła.'
        : needCode
          ? 'Hasło główne się zgadza. Ten plik wymaga jeszcze kodu z aplikacji uwierzytelniającej. Bez telefonu użyj kodu zapasowego.'
          : 'Plik z hostami jest zaszyfrowany.'}
    </p>
    {#if needCode}
      <div class="field">
        <label for="otp">Kod z aplikacji albo kod zapasowy</label>
        <input id="otp" type="text" class="mono" inputmode="numeric" autocomplete="one-time-code" bind:this={codeInput} bind:value={code} class:invalid={!!error} />
      </div>
      {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
      <button class="btn primary" disabled={busy || !looksLikeCode(code)}>
        <Icon name="unlock" />
        {busy ? 'Pracuję...' : 'Odblokuj'}
      </button>
      <button type="button" class="btn back" disabled={busy} onclick={backToPassword}>Wróć do hasła</button>
    {:else}
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
    {/if}
  </form>
</main>

<style>
  main { height: 100%; display: grid; place-items: center; padding: 16px; }
  form { width: min(420px, 100%); background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius-window); padding: 32px; display: flex; flex-direction: column; }
  .logo { width: 56px; height: 56px; display: grid; place-items: center; border: 1px solid var(--border-strong); border-radius: var(--radius-menu); margin-bottom: 16px; }
  h1 { font-size: 20px; margin: 0 0 8px; font-weight: 600; }
  p { margin: 0 0 20px; font-size: 13px; }
  .row { display: flex; gap: 8px; align-items: center; }
  .back { margin-top: 8px; }
  /* overflow-wrap: komunikat może zawierać długą ścieżkę pliku bez spacji. */
  .error { font-size: 13px; margin-bottom: 14px; display: flex; gap: 6px; align-items: center; overflow-wrap: anywhere; border: 1px solid var(--text); border-radius: var(--radius-control); padding: 8px 10px; }
</style>
