<script lang="ts">
  import { api, emptyFields, type FieldsIo, type FolderView, type Id } from './api';
  import FieldsForm from './FieldsForm.svelte';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import { keyImportError, refresh, ui } from './store.svelte';
  import { descendantIds } from './tree';

  let { folder, defaultParent = null, onclose }: { folder: FolderView | null; defaultParent?: Id | null; onclose: () => void } = $props();

  // Dialog jest tworzony od nowa przy każdym otwarciu, więc wartości początkowe są zamierzone.
  // svelte-ignore state_referenced_locally
  let name = $state(folder?.name ?? '');
  // svelte-ignore state_referenced_locally
  let parent = $state<Id | null>(folder ? folder.parent : defaultParent);
  // svelte-ignore state_referenced_locally
  let fields = $state<FieldsIo>(folder ? { ...folder.fields, password: '', clear_password: false, ssh_key: '', ssh_key_passphrase: '', clear_ssh_key: false } : { ...emptyFields(), password: '', ssh_key: '', ssh_key_passphrase: '', clear_ssh_key: false });
  // svelte-ignore state_referenced_locally
  let error = $state('');
  // svelte-ignore state_referenced_locally
  let touched = $state(false);
  // svelte-ignore state_referenced_locally
  let busy = $state(false);
  let keyPassphraseNeeded = $state(false);

  const folders = $derived(ui.doc?.folders ?? []);
  const hosts = $derived(ui.doc?.hosts ?? []);
  const blocked = $derived(folder ? descendantIds(folders, folder.id) : new Set<Id>());
  const nameInvalid = $derived(touched && !name.trim());

  async function save(e: Event) {
    e.preventDefault();
    touched = true;
    if (!name.trim()) return;
    busy = true;
    error = '';
    try {
      await api.saveFolder({ id: folder?.id ?? null, name, parent, fields });
      await refresh();
      onclose();
    } catch (err) {
      const k = keyImportError(err);
      if (k) {
        error = k.message;
        if (k.needsPassphrase) keyPassphraseNeeded = true;
      } else error = String(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title={folder ? 'Edycja katalogu' : 'Nowy katalog'} {onclose} width={540}>
  <form id="folder-form" onsubmit={save}>
    <div class="field">
      <label for="k-name">Nazwa</label>
      <input id="k-name" type="text" bind:value={name} class:invalid={nameInvalid} />
      {#if nameInvalid}<span class="error"><Icon name="alert" size={12} /> Nazwa jest wymagana.</span>{/if}
    </div>
    <div class="field">
      <label for="k-parent">Katalog nadrzędny</label>
      <select id="k-parent" bind:value={parent}>
        <option value={null}>(główny)</option>
        {#each folders.filter((f) => !blocked.has(f.id)) as f (f.id)}<option value={f.id}>{f.name}</option>{/each}
      </select>
    </div>
    <p class="muted note">Ustawienia poniżej dziedziczą hosty i podkatalogi, dopóki nie nadpiszą ich własnymi.</p>
    <FieldsForm bind:fields bind:keyPassphraseNeeded {folders} {hosts} startFolder={parent} protocol={null} />
    {#if error}<div class="error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
  </form>
  {#snippet footer()}
    <button class="btn" type="button" onclick={onclose}>Anuluj</button>
    <button class="btn primary" type="submit" form="folder-form" disabled={busy}>Zapisz</button>
  {/snippet}
</Modal>

<style>
  .note { font-size: 12px; margin: 0 0 14px; }
</style>
