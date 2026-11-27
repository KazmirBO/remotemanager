<script lang="ts">
  import { listen } from '@tauri-apps/api/event';
  import { api, type KeyStatus } from '../api';
  import Icon from '../Icon.svelte';
  import { pinMode, pinReady, touchLabel } from '../mfa';
  import { notify } from '../store.svelte';

  let status = $state<KeyStatus | null>(null);
  let pin = $state('');
  let name = $state('');
  let error = $state('');
  let busy = $state(false);
  // Które dotknięcie klucza właśnie trwa (zdarzenie `key-touch` z backendu).
  let touch = $state<{ step: number; of: number } | null>(null);

  const mode = $derived(pinMode(status?.pin));
  const keys = $derived(status?.keys ?? []);
  const full = $derived(!!status && keys.length >= status.max);
  const ready = $derived(pinReady(mode, pin));
  const removalName = $derived(keys.find((k) => k.id === status?.removal?.id)?.name ?? '');

  $effect(() => {
    void load();
    const unlisten = listen<{ step: number; of: number }>('key-touch', (e) => { touch = e.payload; });
    return () => { void unlisten.then((f) => f()).catch(() => {}); };
  });

  async function load() {
    try {
      status = await api.keyStatus();
    } catch (e) {
      error = String(e);
    }
  }

  async function run(action: () => Promise<void>) {
    busy = true;
    error = '';
    touch = null;
    try {
      await action();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
      touch = null;
    }
  }

  const usedPin = () => (mode === 'app' ? pin : null);

  const add = () => run(async () => {
    status = await api.keyAdd(usedPin(), name);
    name = '';
    notify('Klucz sprzętowy jest dodany.');
  });

  const remove = (id: string) => run(async () => {
    status = await api.keyRemove(id, usedPin());
    if (!status.removal) notify('Klucz sprzętowy jest usunięty.');
  });

  const cancelRemoval = () => run(async () => {
    await api.keyRemoveCancel();
    await load();
  });

  const check = () => run(async () => {
    const found = await api.keyCheck(usedPin());
    notify(`Klucz "${found}" pasuje do pliku.`);
  });

  /** Enter w polach tej sekcji nie może wysłać formularza całych ustawień. */
  const onEnter = (action: () => void, allowed: () => boolean) => (e: KeyboardEvent) => {
    if (e.key === 'Enter') { e.preventDefault(); if (!busy && allowed()) action(); }
  };
</script>

<h3 class="section-title">Klucz sprzętowy przy otwieraniu pliku (FIDO2)</h3>
<p class="form-note">
  Plik otwiera wtedy hasło główne razem z kluczem: sekret klucza jest częścią szyfrowania, więc sam plik i hasło nie wystarczą.
  Każdy zarejestrowany klucz otwiera plik samodzielnie. Zarejestruj dwa i trzymaj drugi w bezpiecznym miejscu: po utracie
  jedynego klucza pliku nie da się odzyskać. Klucz musi mieć ustawiony PIN. Wersje programu starsze niż ta nie otworzą pliku
  z kluczem. Działania w tej sekcji wykonują się od razu.
</p>

{#if status && !status.available}
  <p class="status"><Icon name="info" size={14} /> Ta wersja programu nie obsługuje kluczy sprzętowych na tym systemie.</p>
{:else if status}
  {#if keys.length === 0}
    <p class="status"><Icon name="shield" size={14} /> Wyłączone: plik otwiera samo hasło główne.</p>
  {:else}
    <p class="status">
      <Icon name={keys.length === 1 ? 'alert' : 'shield-check'} size={14} />
      {keys.length === 1 ? 'Włączone, zarejestrowany jeden klucz. Dodaj drugi na wypadek utraty pierwszego.' : `Włączone, zarejestrowane klucze: ${keys.length}.`}
    </p>
    <ul class="keys">
      {#each keys as k (k.id)}
        <li>
          <Icon name="key" size={14} />
          <span class="name">{k.name}</span>
          <button type="button" class="btn compact" disabled={busy || !ready || !!status.removal} onclick={() => remove(k.id)}>
            <Icon name="trash" size={14} /> Usuń
          </button>
        </li>
      {/each}
    </ul>
  {/if}

  {#if status.removal}
    <div class="state" role="status">
      <Icon name="alert" size={20} />
      <div>
        <p>
          Usuwanie klucza "{removalName}" nie jest skończone. Plik dostaje nowy klucz szyfrujący, więc każdy klucz, który zostaje,
          musi go potwierdzić. Podłącz kolejny klucz ({status.removal.waiting.join(', ')}) i dotknij go dwa razy.
        </p>
        <div class="actions">
          <button type="button" class="btn compact" disabled={busy || !ready} onclick={() => remove(status!.removal!.id)}>
            <Icon name="key" size={14} /> {busy ? touchLabel(touch) : 'Użyj kolejnego klucza'}
          </button>
          <button type="button" class="btn compact" disabled={busy} onclick={cancelRemoval}>Anuluj usuwanie</button>
        </div>
      </div>
    </div>
  {/if}

  {#if mode === 'app'}
    <div class="field">
      <label for="key-pin-set">PIN klucza</label>
      <input id="key-pin-set" type="password" autocomplete="off" bind:value={pin} onkeydown={onEnter(() => {}, () => false)} />
      <span class="hint muted">Potrzebny do każdej operacji na kluczu. Program go nie zapisuje.</span>
    </div>
  {:else}
    <p class="form-note">O PIN klucza zapyta system we własnym oknie.</p>
  {/if}

  {#if !full}
    <div class="field">
      <label for="key-name">Nazwa nowego klucza</label>
      <div class="row">
        <input id="key-name" type="text" maxlength="40" placeholder="np. niebieski, zapasowy" autocomplete="off" bind:value={name}
          onkeydown={onEnter(add, () => ready && !!name.trim() && !status?.removal)} />
        <button type="button" class="btn" disabled={busy || !ready || !name.trim() || !!status.removal} onclick={add}>
          <Icon name="plus" size={14} /> Dodaj klucz
        </button>
      </div>
      <span class="hint muted">Przy dodawaniu klucz trzeba dotknąć trzy razy: przy rejestracji i dwukrotnie przy odczycie sekretu.</span>
    </div>
  {/if}
  {#if keys.length > 0}
    <div class="actions">
      <button type="button" class="btn compact" disabled={busy || !ready} onclick={check}>
        <Icon name="check-circle" size={14} /> Sprawdź klucz
      </button>
      <span class="note muted">Sprawdza, czy podłączony klucz otworzy ten plik, niczego nie zmieniając.</span>
    </div>
  {/if}
  {#if busy}<p class="status waiting" role="status"><Icon name="key" size={14} /> {touchLabel(touch)}</p>{/if}
{/if}
{#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> <span>{error}</span></div>{/if}

<style>
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .row input { flex: 1; min-width: 120px; }
  .status { display: flex; gap: 6px; align-items: center; font-size: 13px; margin: 0 0 12px; }
  .waiting { margin-top: 12px; font-weight: 600; }
  .keys { list-style: none; margin: 0 0 14px; padding: 0; border: 1px solid var(--border); border-radius: var(--radius-control); }
  .keys li { display: flex; gap: 8px; align-items: center; padding: 6px 10px; font-size: 13px; }
  .keys li + li { border-top: 1px solid var(--border); }
  .name { flex: 1; overflow-wrap: anywhere; }
  .state { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--border-strong); border-radius: var(--radius-control); padding: 12px; margin-bottom: 14px; font-size: 13px; }
  .state p { margin: 0 0 8px; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: 8px; }
  .note { font-size: 12px; }
  .error { margin-top: 12px; font-size: 13px; display: flex; gap: 6px; align-items: flex-start; overflow-wrap: anywhere; }
</style>
