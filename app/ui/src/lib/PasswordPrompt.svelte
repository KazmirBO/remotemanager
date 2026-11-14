<script lang="ts">
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { ui } from './store.svelte';

  let password = $state('');
  let show = $state(false);
  const prompt = $derived(ui.passwordQueue[0]);
  // Nowy monit (np. dla innego hosta) zaczyna się od pustego pola, żeby hasło nie poszło pod zły adres.
  $effect(() => {
    void prompt;
    password = '';
    show = false;
  });

  function submit(e: Event) {
    e.preventDefault();
    prompt?.resolve(password);
    password = '';
  }
  function cancel() {
    prompt?.resolve(null);
    password = '';
  }
</script>

{#if prompt}
  <Modal title="Hasło dla {prompt.title}" onclose={cancel} width={460}>
    <form id="pw-prompt" onsubmit={submit}>
      <p class="muted reason">{prompt.reason}</p>
      <div class="field">
        <label for="pp-pw">Hasło (tylko na tę sesję, nie jest zapisywane)</label>
        <div class="row">
          <input id="pp-pw" type={show ? 'text' : 'password'} bind:value={password} autocomplete="off" />
          <button type="button" class="icon-btn" aria-label={show ? 'Ukryj hasło' : 'Pokaż hasło'} onclick={() => (show = !show)}>
            <Icon name={show ? 'eye-off' : 'eye'} />
          </button>
        </div>
      </div>
    </form>
    {#snippet footer()}
      <button class="btn" type="button" onclick={cancel}>Anuluj</button>
      <button class="btn primary" type="submit" form="pw-prompt" disabled={!password}>Połącz</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .reason { margin: 0 0 16px; font-size: 13px; }
  .row { display: flex; gap: 8px; align-items: center; }
</style>
