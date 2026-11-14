<script lang="ts">
  import type { FieldsIo, FolderView, HostView, Id, Protocol } from './api';
  import { inherited, inheritsPassword, type InheritableKey } from './tree';
  import Icon from './Icon.svelte';
  import { SCHEMES } from './terminalThemes';

  let {
    fields = $bindable(),
    folders,
    hosts,
    startFolder,
    protocol,
    selfId = null,
  }: {
    fields: FieldsIo;
    folders: FolderView[];
    hosts: HostView[];
    /** Katalog, od którego zaczyna się dziedziczenie (dla katalogu: jego rodzic). */
    startFolder: Id | null;
    /** `null` dla katalogu (pokazuje wszystkie pola). */
    protocol: Protocol | null;
    selfId?: Id | null;
  } = $props();

  const hint = (key: InheritableKey) => {
    const v = inherited(folders, startFolder, key);
    return v ? `Dziedziczone z „${v.from}”: ${v.value}` : null;
  };
  const jumpCandidates = $derived(hosts.filter((h) => h.protocol === 'ssh' && h.id !== selfId));
  const inheritedPw = $derived(inheritsPassword(folders, startFolder));
  const kerberosHint = $derived(inherited(folders, startFolder, 'rdp_kerberos'));
</script>

<div class="field">
  <label for="f-port">Port</label>
  <input id="f-port" type="number" min="1" max="65535" bind:value={fields.port}
    placeholder={protocol === 'rdp' ? '3389' : protocol === 'ssh' ? '22' : 'domyślny dla protokołu'} />
  {#if fields.port === null && hint('port')}<span class="hint"><Icon name="route" size={12} /> {hint('port')}</span>{/if}
</div>

<div class="field">
  <label for="f-user">Użytkownik</label>
  <input id="f-user" type="text" bind:value={fields.username} autocomplete="off" />
  {#if !fields.username && hint('username')}<span class="hint"><Icon name="route" size={12} /> {hint('username')}</span>{/if}
</div>

{#if protocol !== 'ssh'}
  <div class="field">
    <label for="f-domain">Domena (RDP)</label>
    <input id="f-domain" type="text" bind:value={fields.domain} autocomplete="off" />
    {#if !fields.domain && hint('domain')}<span class="hint"><Icon name="route" size={12} /> {hint('domain')}</span>{/if}
  </div>
{/if}

<div class="field">
  <label for="f-pw">Hasło</label>
  <input id="f-pw" type="password" bind:value={fields.password} autocomplete="new-password"
    placeholder={fields.has_password ? 'Zapisane. Wpisz, aby zmienić.' : 'Puste: agent SSH albo dziedziczenie'} disabled={fields.clear_password} />
  {#if fields.has_password}
    <span class="hint">
      <Icon name="key" size={12} />
      {fields.clear_password ? 'Zapisane hasło zostanie usunięte.' : 'Hasło jest zapisane w zaszyfrowanym pliku.'}
      <button type="button" class="link" onclick={() => (fields.clear_password = !fields.clear_password)}>
        {fields.clear_password ? 'Cofnij' : 'Usuń'}
      </button>
    </span>
  {:else if inheritedPw}
    <span class="hint"><Icon name="route" size={12} /> Hasło dziedziczone z „{inheritedPw}”.</span>
  {/if}
</div>

{#if protocol !== 'ssh'}
  <div class="field">
    <label for="f-krb">Uwierzytelnianie Kerberos (RDP)</label>
    <!-- Trzy stany: "nie" musi dać się wybrać jawnie, żeby wyłączyć Kerberos odziedziczony z katalogu. -->
    <select id="f-krb" value={fields.rdp_kerberos === null ? 'inherit' : fields.rdp_kerberos ? 'yes' : 'no'}
      onchange={(e) => { const v = e.currentTarget.value; fields.rdp_kerberos = v === 'inherit' ? null : v === 'yes'; }}>
      <option value="inherit">Dziedzicz{kerberosHint ? ` (${kerberosHint.value ? 'tak' : 'nie'})` : ' (nie)'}</option>
      <option value="yes">Tak</option>
      <option value="no">Nie (NTLM)</option>
    </select>
    {#if fields.rdp_kerberos === null && kerberosHint}
      <span class="hint"><Icon name="route" size={12} /> Dziedziczone z „{kerberosHint.from}”: {kerberosHint.value ? 'tak' : 'nie'}</span>
    {/if}
    <span class="hint">Wymaga pełnej nazwy hosta (np. dc01.firma.local) i hasła. Brak logowania jednokrotnego z ccache.</span>
  </div>
  {#if fields.rdp_kerberos ?? kerberosHint?.value}
    <div class="field">
      <label for="f-kdc">Adres KDC albo proxy KKDCP (opcjonalnie)</label>
      <input id="f-kdc" type="text" bind:value={fields.rdp_kdc} placeholder="tcp://kdc.firma.local:88" class="mono" />
      {#if !fields.rdp_kdc && hint('rdp_kdc')}<span class="hint"><Icon name="route" size={12} /> {hint('rdp_kdc')}</span>{/if}
    </div>
  {/if}
{/if}

{#if protocol !== 'rdp'}
  <div class="field">
    <label for="f-jump">Bastion (ProxyJump)</label>
    <select id="f-jump" bind:value={fields.jump_host}>
      <option value={null}>Brak{hint('jump_host') ? ' (dziedzicz)' : ''}</option>
      {#each jumpCandidates as h (h.id)}<option value={h.id}>{h.name} ({h.address})</option>{/each}
    </select>
    {#if fields.jump_host === null && hint('jump_host')}
      {@const own = inherited(folders, startFolder, 'jump_host')}
      {@const v = inherited(folders, startFolder, 'jump_host', selfId ?? undefined)}
      {#if v}
        <span class="hint">
          <Icon name="route" size={12} /> Dziedziczone z „{v.from}”: {hosts.find((h) => h.id === v.value)?.name ?? '?'}{own?.value === selfId ? ` (katalog „${own.from}” wskazuje ten host, więc jest pomijany)` : ''}
        </span>
      {:else}
        <span class="hint"><Icon name="route" size={12} /> Katalog „{own?.from}” wskazuje ten host jako bastion, więc on sam łączy się bezpośrednio.</span>
      {/if}
    {/if}
  </div>
{/if}

{#if protocol !== 'rdp'}
  <div class="field">
    <label for="f-scheme">Schemat terminala</label>
    <select id="f-scheme" bind:value={fields.terminal_scheme}>
      <option value={null}>Dziedzicz{hint('terminal_scheme') ? '' : ' (domyślny z ustawień)'}</option>
      {#each Object.entries(SCHEMES) as [id, name] (id)}<option value={id}>{name}</option>{/each}
    </select>
    {#if fields.terminal_scheme === null && hint('terminal_scheme')}
      <span class="hint"><Icon name="route" size={12} /> {hint('terminal_scheme')}</span>
    {/if}
  </div>
{/if}

<style>
  .link { background: none; border: none; padding: 0; text-decoration: underline; color: var(--text); font-size: 12px; }
</style>
