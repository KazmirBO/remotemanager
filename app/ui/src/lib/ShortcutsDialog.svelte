<script lang="ts">
  import { api, type Settings } from './api';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { ACTIONS, binding, comboFromEvent, findConflict, hasScancode, validCombo } from './shortcuts';
  import { applyTheme, notify, refresh, ui } from './store.svelte';

  let { onclose }: { onclose: () => void } = $props();
  // svelte-ignore state_referenced_locally
  let settings = $state<Settings>(structuredClone($state.snapshot(ui.doc!.settings)));
  let capturing = $state<string | null>(null);
  let error = $state('');
  let busy = $state(false);

  const label = (id: string) => ACTIONS.find((a) => a.id === id)!.label;

  function capture(e: KeyboardEvent) {
    if (capturing === null) return;
    e.preventDefault();
    e.stopPropagation();
    if (e.key === 'Escape') {
      capturing = null;
      return;
    }
    const combo = comboFromEvent(e);
    if (!combo) return; // sam modyfikator: czekamy na właściwy klawisz
    if (!validCombo(combo)) {
      error = 'Skrót musi zawierać Ctrl, Alt albo Meta (albo być klawiszem funkcyjnym).';
      return;
    }
    if (capturing === 'release_keys' && !hasScancode(combo)) {
      error = 'Tego klawisza nie da się użyć do zwolnienia klawiszy: zdalny pulpit nie ma dla niego kodu klawisza. Wybierz inny, np. klawisz funkcyjny F1-F12.';
      return;
    }
    const clash = findConflict(settings, capturing, combo);
    if (clash) {
      error = `Skrót ${combo} jest już używany przez: ${label(clash)}.`;
      return;
    }
    settings.shortcuts[capturing] = combo;
    error = '';
    capturing = null;
  }

  function reset(id: string) {
    delete settings.shortcuts[id];
  }

  async function save() {
    busy = true;
    try {
      await api.saveSettings($state.snapshot(settings));
      await refresh();
      applyTheme(settings);
      notify('Zapisano skróty klawiszowe.');
      onclose();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onkeydowncapture={capture} />

<Modal title="Skróty klawiszowe" {onclose} width={520}>
  <p class="muted note">Kliknij „Zmień” i naciśnij nową kombinację. Esc anuluje.</p>
  <ul>
    {#each ACTIONS as a (a.id)}
      <li>
        <span>{a.label}</span>
        <span class="right">
          <kbd class:capturing={capturing === a.id}>{capturing === a.id ? 'Naciśnij skrót...' : binding(settings, a.id)}</kbd>
          <button class="btn compact" onclick={() => { capturing = a.id; error = ''; }}>Zmień</button>
          <button class="icon-btn" aria-label="Przywróć domyślny skrót: {a.label}" title="Przywróć domyślny" disabled={!settings.shortcuts[a.id]} onclick={() => reset(a.id)}>
            <Icon name="refresh" size={14} />
          </button>
        </span>
      </li>
    {/each}
  </ul>
  {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
  {#snippet footer()}
    <button class="btn" onclick={onclose}>Anuluj</button>
    <button class="btn primary" onclick={save} disabled={busy}>Zapisz</button>
  {/snippet}
</Modal>

<style>
  .note { font-size: 12px; margin: 0 0 12px; }
  ul { list-style: none; margin: 0; padding: 0; border: 1px solid var(--border); border-radius: var(--radius-control); }
  li { display: flex; justify-content: space-between; align-items: center; min-height: 48px; padding: 0 12px; gap: 12px; }
  li + li { border-top: 1px solid var(--border); }
  .right { display: flex; align-items: center; gap: 8px; }
  kbd { font-family: var(--font-mono); font-size: 12px; border: 1px solid var(--border-strong); border-radius: var(--radius-badge); padding: 3px 8px; background: var(--surface); min-width: 70px; text-align: center; }
  kbd.capturing { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
  .error { font-size: 13px; display: flex; gap: 6px; align-items: center; margin-top: 12px; }
</style>
