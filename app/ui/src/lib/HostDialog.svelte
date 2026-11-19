<script lang="ts">
  import { api, emptyFields, type FieldsIo, type HostView, type Id, type Protocol } from './api';
  import FieldsForm from './FieldsForm.svelte';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import Tabs from './Tabs.svelte';
  import { keyImportError, refresh, ui } from './store.svelte';
  import { errorTab, TAB_LABELS, visibleTabs, type HostTab } from './hostTabs';

  export interface Prefill { protocol: Protocol; address: string; port: number | null; username: string | null; domain: string | null }
  let { host, defaultFolder = null, prefill = null, onclose }: {
    host: HostView | null; defaultFolder?: Id | null; prefill?: Prefill | null; onclose: () => void;
  } = $props();

  // Dialog jest tworzony od nowa przy każdym otwarciu, więc wartości początkowe są zamierzone.
  // svelte-ignore state_referenced_locally
  let name = $state(host?.name ?? prefill?.address ?? '');
  // svelte-ignore state_referenced_locally
  let address = $state(host?.address ?? prefill?.address ?? '');
  // svelte-ignore state_referenced_locally
  let protocol = $state<Protocol>(host?.protocol ?? prefill?.protocol ?? 'ssh');
  // svelte-ignore state_referenced_locally
  let folder = $state<Id | null>(host ? host.folder : defaultFolder);
  // svelte-ignore state_referenced_locally
  let notes = $state(host?.notes ?? '');
  // svelte-ignore state_referenced_locally
  let fields = $state<FieldsIo>(
    host
      ? { ...host.fields, password: '', clear_password: false, ssh_key: '', ssh_key_passphrase: '', clear_ssh_key: false }
      : { ...emptyFields(), port: prefill?.port ?? null, username: prefill?.username ?? null, domain: prefill?.domain ?? null, password: '', ssh_key: '', ssh_key_passphrase: '', clear_ssh_key: false },
  );
  // svelte-ignore state_referenced_locally
  let error = $state('');
  // svelte-ignore state_referenced_locally
  let busy = $state(false);
  let keyPassphraseNeeded = $state(false);
  // svelte-ignore state_referenced_locally
  let touched = $state(false);

  let tab = $state<string>('general');
  /** Zakładka, w której jest błąd ostatniej próby zapisu. */
  let badTab = $state<HostTab | null>(null);
  const tabItems = $derived(
    visibleTabs(protocol).map((id) => ({ id, label: TAB_LABELS[id], invalid: id === badTab })),
  );
  function flag(t: HostTab | null) {
    badTab = t;
    if (t) tab = t;
  }

  const folders = $derived(ui.doc?.folders ?? []);
  const hosts = $derived(ui.doc?.hosts ?? []);
  const nameInvalid = $derived(touched && !name.trim());
  const addressInvalid = $derived(touched && !address.trim());

  async function save(e: Event) {
    e.preventDefault();
    touched = true;
    badTab = null;
    error = '';
    if (!name.trim() || !address.trim()) {
      error = 'Nazwa i adres hosta są wymagane.';
      flag('general');
      return;
    }
    busy = true;
    try {
      await api.saveHost({ id: host?.id ?? null, name, address, protocol, folder, notes, fields });
      await refresh();
      onclose();
    } catch (err) {
      const k = keyImportError(err);
      if (k) {
        error = k.message;
        if (k.needsPassphrase) keyPassphraseNeeded = true;
        flag('login');
      } else {
        error = String(err);
        flag(errorTab(error));
      }
    } finally {
      busy = false;
    }
  }
</script>

<Modal title={host ? 'Edycja hosta' : prefill ? 'Połączenie z linku' : 'Nowy host'} {onclose} width={600} height={620} flush>
  <form id="host-form" class="form-fill" novalidate onsubmit={save}>
    <Tabs label="Ustawienia hosta" idPrefix="host" items={tabItems} bind:selected={tab}>
      {#snippet panel(id)}
        {#if id === 'general'}
          {#if prefill}
            <p class="muted link-note"><Icon name="link" size={14} /> Link nie łączy automatycznie. Sprawdź dane, zapisz hosta, a potem połącz się z panelu.</p>
          {/if}
          <div class="field">
            <label for="h-name">Nazwa</label>
            <input id="h-name" type="text" bind:value={name} class:invalid={nameInvalid} />
            {#if nameInvalid}<span class="error"><Icon name="alert" size={12} /> Nazwa jest wymagana.</span>{/if}
          </div>
          <div class="field">
            <label for="h-addr">Adres</label>
            <input id="h-addr" type="text" bind:value={address} class:invalid={addressInvalid} placeholder="host.example albo 10.0.0.5" />
            {#if addressInvalid}<span class="error"><Icon name="alert" size={12} /> Adres jest wymagany.</span>{/if}
          </div>
          <div class="two">
            <div class="field">
              <label for="h-proto">Protokół</label>
              <select id="h-proto" bind:value={protocol}>
                <option value="ssh">SSH</option>
                <option value="rdp">RDP</option>
              </select>
            </div>
            <div class="field">
              <label for="h-folder">Katalog</label>
              <select id="h-folder" bind:value={folder}>
                <option value={null}>(główny)</option>
                {#each folders as f (f.id)}<option value={f.id}>{f.name}</option>{/each}
              </select>
            </div>
          </div>
          <div class="field">
            <label for="h-notes">Notatki</label>
            <textarea id="h-notes" bind:value={notes}></textarea>
          </div>
        {:else if id === 'login'}
          <FieldsForm section="login" bind:fields bind:keyPassphraseNeeded {folders} {hosts} startFolder={folder} {protocol} selfId={host?.id ?? null} />
        {:else if id === 'connection' || id === 'terminal' || id === 'redirects'}
          <FieldsForm section={id} bind:fields {folders} {hosts} startFolder={folder} {protocol} selfId={host?.id ?? null} />
        {/if}
      {/snippet}
    </Tabs>
  </form>
  {#snippet footer()}
    {#if error}<div class="form-error error" role="alert"><Icon name="alert" size={14} /> {error}</div>{/if}
    <button class="btn" type="button" onclick={onclose}>Anuluj</button>
    <button class="btn primary" type="submit" form="host-form" disabled={busy}>Zapisz</button>
  {/snippet}
</Modal>

<style>
  .link-note { font-size: 12px; margin: 0 0 14px; display: flex; gap: 6px; align-items: flex-start; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
</style>
