<script lang="ts">
  import { api, type TrustRequest } from './api';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import { notify } from './store.svelte';

  let { request, ondone }: { request: TrustRequest; ondone: () => void } = $props();
  const changed = $derived(request.previous !== null);
  const rdp = $derived(request.protocol === 'rdp');

  // Kolejne pytanie pojawia się w tym samym miejscu, więc przez chwilę po pokazaniu przyciski są
  // nieaktywne: podwójne kliknięcie w poprzednim oknie nie zatwierdzi klucza bez przeczytania odcisku.
  let ready = $state(false);
  $effect(() => {
    const t = setTimeout(() => (ready = true), 500);
    return () => clearTimeout(t);
  });

  // Odpowiedź idzie raz: drugie kliknięcie albo Escape w trakcie wywołania nie może zdjąć kolejnego pytania.
  let answering = false;
  async function answer(accept: boolean, remember: boolean) {
    if (answering) return;
    answering = true;
    try {
      await api.answerTrust(request.id, accept, remember);
    } catch (e) {
      if (accept) notify(String(e), true);
    }
    ondone();
  }
</script>

<Modal title={rdp ? (changed ? 'Certyfikat serwera się zmienił' : 'Nowy certyfikat serwera') : changed ? 'Klucz hosta się zmienił' : 'Nowy klucz hosta'} onclose={() => answer(false, false)} width={560}>
  <div class="head">
    <Icon name={changed ? 'alert' : 'shield'} size={28} />
    <p>
      {#if changed}
        {rdp ? 'Certyfikat' : 'Klucz hosta'} <b>{request.host}:{request.port}</b> różni się od zapamiętanego. Może to oznaczać podszywanie się pod serwer. Kontynuuj tylko, jeśli znasz przyczynę zmiany.
      {:else}
        Łączysz się z <b>{request.host}:{request.port}</b> po raz pierwszy. Porównaj odcisk {rdp ? 'certyfikatu' : 'klucza'} z tym, który podał administrator serwera. Hasło zostanie wysłane dopiero po Twojej zgodzie.
      {/if}
    </p>
  </div>
  <dl>
    <dt>Algorytm</dt><dd class="mono">{request.algorithm}</dd>
    <dt>Odcisk</dt><dd class="mono">{request.fingerprint}</dd>
    {#if changed}<dt>Poprzedni</dt><dd class="mono">{request.previous}</dd>{/if}
  </dl>
  {#snippet footer()}
    <button class="btn" onclick={() => answer(false, false)}>Odrzuć</button>
    <button class="btn" disabled={!ready} onclick={() => answer(true, false)}>Połącz jednorazowo</button>
    <button class="btn primary" disabled={!ready} onclick={() => answer(true, true)}>{changed ? (rdp ? 'Zaufaj nowemu certyfikatowi' : 'Zaufaj nowemu kluczowi') : 'Zapamiętaj i połącz'}</button>
  {/snippet}
</Modal>

<style>
  .head { display: flex; gap: 16px; align-items: flex-start; }
  .head p { margin: 0 0 16px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; margin: 0; }
  dt { color: var(--text-muted); font-size: 13px; }
  dd { margin: 0; word-break: break-all; }
</style>
