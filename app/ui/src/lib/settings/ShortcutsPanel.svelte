<script lang="ts">
  import type { Settings } from '../api';
  import Icon from '../Icon.svelte';
  import { ACTIONS, OFF, REQUIRED_ACTIONS, binding, comboFromEvent, findConflict, hasScancode, validCombo } from '../shortcuts';

  let { settings = $bindable() }: { settings: Settings } = $props();
  let capturing = $state<string | null>(null);
  let error = $state('');

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

  /** Wyłącza skrót akcji. Akcja bez skrótu domyślnego wraca po prostu do stanu "brak". */
  function disable(id: string) {
    const def = ACTIONS.find((a) => a.id === id)!.default;
    if (def) settings.shortcuts[id] = OFF;
    else delete settings.shortcuts[id];
    error = '';
  }
</script>

<svelte:window onkeydowncapture={capture} />

<p class="muted note">Kliknij „Zmień” i naciśnij nową kombinację. Esc anuluje. Przypisany skrót działa także w sesjach, więc ta kombinacja przestaje docierać do zdalnej powłoki i pulpitu (poza trybem przechwytywania klawiszy RDP). Zmiany zapisuje przycisk Zapisz.</p>
  <ul>
    {#each ACTIONS as a (a.id)}
      <li>
        <span>{a.label}</span>
        <span class="right">
          <kbd class:capturing={capturing === a.id} class:none={capturing !== a.id && !binding(settings, a.id)}>{capturing === a.id ? 'Naciśnij skrót...' : binding(settings, a.id) || 'brak'}</kbd>
          <button type="button" class="btn compact" onclick={() => { capturing = a.id; error = ''; }}>Zmień</button>
          <button type="button" class="icon-btn" aria-label="Wyłącz skrót: {a.label}" title="Wyłącz skrót" disabled={REQUIRED_ACTIONS.has(a.id) || !binding(settings, a.id)} onclick={() => disable(a.id)}>
            <Icon name="close" size={14} />
          </button>
          <button type="button" class="icon-btn" aria-label="Przywróć domyślny skrót: {a.label}" title={a.default ? `Przywróć domyślny (${a.default})` : 'Przywróć domyślny (brak)'} disabled={!settings.shortcuts[a.id]} onclick={() => reset(a.id)}>
            <Icon name="refresh" size={14} />
          </button>
        </span>
      </li>
    {/each}
  </ul>
  {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}

<style>
  .note { font-size: 12px; margin: 0 0 12px; }
  /* Lista przewija się razem z panelem kategorii. */
  ul { list-style: none; margin: 0; padding: 0; border: 1px solid var(--border); border-radius: var(--radius-control); }
  li { display: flex; justify-content: space-between; align-items: center; min-height: 48px; padding: 0 12px; gap: 12px; }
  li + li { border-top: 1px solid var(--border); }
  .right { display: flex; align-items: center; gap: 8px; }
  kbd { font-family: var(--font-mono); font-size: 12px; border: 1px solid var(--border-strong); border-radius: var(--radius-badge); padding: 3px 8px; background: var(--surface); min-width: 70px; text-align: center; }
  kbd.capturing { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
  /* Brak skrótu: obramowanie przerywane i przygaszony tekst, nie sam kolor. */
  kbd.none { border-style: dashed; color: var(--text-muted); background: transparent; }
  .error { font-size: 13px; display: flex; gap: 6px; align-items: center; margin-top: 12px; }
</style>
