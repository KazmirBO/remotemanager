<script lang="ts">
  import { api } from './api';
  import { afterUnlock, ui } from './store.svelte';
  import Icon from './Icon.svelte';
  import { looksLikeCode, pinMode, pinReady, unlockStep, type PinMode, type UnlockStep } from './mfa';

  const creating = $derived(ui.phase === 'missing');
  let password = $state('');
  let repeat = $state('');
  let error = $state('');
  let busy = $state(false);
  let show = $state(false);
  // Kolejne kroki po haśle: klucz sprzętowy (plik jest jeszcze zaszyfrowany, hasło sprawdzi się
  // dopiero razem z kluczem), potem kod z aplikacji uwierzytelniającej.
  let step = $state<'password' | 'key' | 'code'>('password');
  let keyPin = $state<PinMode>('app');
  let pin = $state('');
  let code = $state('');
  let pinInput = $state<HTMLInputElement>();
  let codeInput = $state<HTMLInputElement>();

  $effect(() => {
    if (step === 'code') codeInput?.focus();
    if (step === 'key') pinInput?.focus();
  });

  /** Przechodzi do kroku, którego żąda backend; zwraca false, gdy to zwykły błąd. */
  function advance(next: UnlockStep): boolean {
    if (next.kind === 'needs_key') {
      keyPin = pinMode(next.message);
      pin = '';
      step = 'key';
      return true;
    }
    if (next.kind === 'needs_code') {
      code = '';
      step = 'code';
      return true;
    }
    return false;
  }

  async function submit(e: Event) {
    e.preventDefault();
    error = '';
    if (step === 'code') return submitCode();
    if (step === 'key') return submitKey();
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
      const next = unlockStep(err);
      // Hasło zostało przyjęte przez backend: nie trzymamy go dłużej w polu.
      if (advance(next)) password = '';
      else error = next.message;
    } finally {
      busy = false;
    }
  }

  async function submitKey() {
    busy = true;
    try {
      await api.unlockKey(keyPin === 'app' ? pin : null);
      pin = '';
      step = 'password';
      await afterUnlock();
    } catch (err) {
      const next = unlockStep(err);
      pin = '';
      if (advance(next)) return;
      error = next.message;
      // Złe hasło wychodzi dopiero z kluczem, podobnie jak upływ czasu: wracamy do hasła.
      if (next.kind !== 'bad_key') step = 'password';
    } finally {
      busy = false;
    }
  }

  async function submitCode() {
    busy = true;
    try {
      await api.unlockTotp(code);
      code = '';
      step = 'password';
      await afterUnlock();
    } catch (err) {
      const next = unlockStep(err);
      error = next.message;
      code = '';
      // Za dużo prób albo minął czas: odblokowanie zaczyna się od hasła.
      if (next.kind !== 'bad_code') step = 'password';
    } finally {
      busy = false;
    }
  }

  function backToPassword() {
    step = 'password';
    code = '';
    pin = '';
    error = '';
  }

  const icon = $derived(creating ? 'shield-check' : step === 'key' ? 'key' : step === 'code' ? 'shield' : 'lock');
  const title = $derived(
    creating ? 'Pierwsze uruchomienie'
      : step === 'key' ? 'Użyj klucza sprzętowego'
      : step === 'code' ? 'Podaj kod jednorazowy'
      : 'Odblokuj hasłem głównym',
  );
  const intro = $derived(
    creating
      ? 'Hosty, hasła i klucze będą zapisane w pliku zaszyfrowanym hasłem głównym. Nie da się go odzyskać bez tego hasła.'
      : step === 'key'
        ? keyPin === 'app'
          ? 'Ten plik otwiera hasło główne razem z kluczem sprzętowym. Włóż klucz, podaj jego PIN i dotknij klucza, gdy zacznie migać. Hasło sprawdzi się dopiero razem z kluczem.'
          : 'Ten plik otwiera hasło główne razem z kluczem sprzętowym. Włóż klucz: system zapyta o jego PIN i poprosi o dotknięcie. Hasło sprawdzi się dopiero razem z kluczem.'
        : step === 'code'
          ? 'Hasło główne się zgadza. Ten plik wymaga jeszcze kodu z aplikacji uwierzytelniającej. Bez telefonu użyj kodu zapasowego.'
          : 'Plik z hostami jest zaszyfrowany.',
  );
</script>

<main>
  <form onsubmit={submit}>
    <div class="logo"><Icon name={icon} size={28} /></div>
    <h1>{title}</h1>
    <p class="muted">{intro}</p>
    {#if step === 'key'}
      {#if keyPin === 'app'}
        <div class="field">
          <label for="key-pin">PIN klucza</label>
          <input id="key-pin" type="password" autocomplete="off" bind:this={pinInput} bind:value={pin} class:invalid={!!error} />
        </div>
      {/if}
      {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
      <button class="btn primary" disabled={busy || !pinReady(keyPin, pin)}>
        <Icon name="key" />
        {busy ? 'Dotknij klucza...' : 'Użyj klucza'}
      </button>
      <button type="button" class="btn back" disabled={busy} onclick={backToPassword}>Wróć do hasła</button>
    {:else if step === 'code'}
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
