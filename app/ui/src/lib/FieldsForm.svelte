<script lang="ts">
  import type { FieldsIo, FolderView, HostView, Id, Protocol } from './api';
  import { ui } from './store.svelte';
  import { inherited, inheritsPassword, inheritsSshKey, type InheritableKey } from './tree';
  import Icon from './Icon.svelte';
  import { SCHEMES } from './terminalThemes';

  let {
    fields = $bindable(),
    folders,
    hosts,
    startFolder,
    protocol,
    selfId = null,
    section,
    keyPassphraseNeeded = $bindable(false),
  }: {
    fields: FieldsIo;
    folders: FolderView[];
    hosts: HostView[];
    /** Katalog, od którego zaczyna się dziedziczenie (dla katalogu: jego rodzic). */
    startFolder: Id | null;
    /** `null` dla katalogu (pokazuje wszystkie pola). */
    protocol: Protocol | null;
    selfId?: Id | null;
    /** Sekcja (zakładka okna), której pola pokazujemy. */
    section: 'login' | 'connection' | 'terminal' | 'redirects';
    /** Ustawia dialog, gdy import klucza wymaga hasła klucza. */
    keyPassphraseNeeded?: boolean;
  } = $props();

  const hint = (key: InheritableKey) => {
    const v = inherited(folders, startFolder, key);
    return v ? `Dziedziczone z „${v.from}”: ${v.value}` : null;
  };
  const jumpCandidates = $derived(hosts.filter((h) => h.protocol === 'ssh' && h.id !== selfId));
  const inheritedPw = $derived(inheritsPassword(folders, startFolder));
  const inheritedKey = $derived(inheritsSshKey(folders, startFolder));
  let keyError = $state('');
  let keyFile = $state<HTMLInputElement>();
  async function loadKeyFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    keyError = '';
    if (!file) return;
    if (file.size > 65536) {
      keyError = 'Plik klucza jest za duży (limit 64 KiB).';
      return;
    }
    try {
      fields.ssh_key = await file.text();
    } catch {
      keyError = 'Nie można odczytać pliku klucza.';
    }
  }
  const profileName = (v: unknown) => (v === 'slow' ? 'wolne' : 'szybkie');
  const profileHint = $derived(inherited(folders, startFolder, 'rdp_profile'));
  const kerberosHint = $derived(inherited(folders, startFolder, 'rdp_kerberos'));
  const webauthnHint = $derived(inherited(folders, startFolder, 'rdp_webauthn'));
  const cardName = (v: unknown) => (v === 'on' ? 'tak' : v === 'neutral' ? 'neutralne nazwy' : 'nie');
  const cardHint = $derived(inherited(folders, startFolder, 'rdp_smartcard'));
  const fontHint = $derived(inherited(folders, startFolder, 'terminal_font_size'));
  const settingsTerm = $derived(ui.doc?.settings.ssh_term ?? 'xterm-256color');
  const settingsFont = $derived(ui.doc?.settings.terminal_font_size ?? 13);
  const legacyHint = $derived(inherited(folders, startFolder, 'ssh_legacy'));
</script>

{#if section === 'login'}
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
    placeholder={fields.has_password ? 'Zapisane. Wpisz, aby zmienić.' : 'Puste: klucz, agent SSH albo dziedziczenie'} disabled={fields.clear_password} />
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

{#if protocol !== 'rdp'}
  <div class="field">
    <label for="f-key">Klucz SSH</label>
    {#if fields.has_ssh_key}
      <span class="hint mono">
        <Icon name="key" size={12} /> {fields.ssh_key_algorithm} {fields.ssh_key_fingerprint}
      </span>
      <span class="hint">
        {fields.clear_ssh_key ? 'Zapisany klucz zostanie usunięty.' : 'Klucz jest zapisany w zaszyfrowanym pliku bez hasła.'}
        <button type="button" class="link" onclick={() => (fields.clear_ssh_key = !fields.clear_ssh_key)}>
          {fields.clear_ssh_key ? 'Cofnij' : 'Usuń'}
        </button>
      </span>
    {/if}
    <textarea id="f-key" class="mono" rows="4" bind:value={fields.ssh_key} autocomplete="off" spellcheck="false"
      disabled={fields.clear_ssh_key}
      placeholder={fields.has_ssh_key ? 'Wklej nowy klucz, aby zastąpić zapisany.' : 'Wklej klucz prywatny (OpenSSH, PEM, PKCS#8, PuTTY .ppk)'}></textarea>
    <div>
      <button type="button" class="btn" disabled={fields.clear_ssh_key} onclick={() => keyFile?.click()}>Wczytaj z pliku...</button>
      <input bind:this={keyFile} type="file" hidden onchange={loadKeyFile} />
    </div>
    {#if keyError}<span class="error"><Icon name="alert" size={12} /> {keyError}</span>{/if}
    {#if keyPassphraseNeeded}
      <label for="f-key-pass">Hasło klucza (tylko do importu, nie jest zapisywane)</label>
      <input id="f-key-pass" type="password" bind:value={fields.ssh_key_passphrase} autocomplete="off" />
    {/if}
    <span class="hint">Klucz jest odszyfrowywany przy zapisie i chroniony hasłem głównym pliku.</span>
    {#if !fields.has_ssh_key && !fields.ssh_key?.trim() && inheritedKey}
      <span class="hint"><Icon name="route" size={12} /> Klucz dziedziczony z „{inheritedKey.from}”: <span class="mono">{inheritedKey.algorithm} {inheritedKey.fingerprint}</span></span>
    {/if}
  </div>
  <div class="field">
    <label for="f-key-path">Plik klucza SSH</label>
    <input id="f-key-path" type="text" class="mono" bind:value={fields.ssh_key_path} autocomplete="off"
      placeholder="/home/ja/.ssh/id_ed25519 albo ~/.ssh/id_ed25519" />
    {#if !fields.ssh_key_path && hint('ssh_key_path')}<span class="hint"><Icon name="route" size={12} /> {hint('ssh_key_path')}</span>{/if}
    <span class="hint">Plik jest czytany przy łączeniu. Zaszyfrowany klucz wymaga hasła przy każdym połączeniu (na bastionie nie działa: zaimportuj go albo użyj agenta).</span>
    <span class="hint">Kolejność logowania: klucz z pliku z hostami, plik klucza, agent SSH, zapisane hasło.</span>
  </div>
{/if}

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
{:else if section === 'connection'}
<div class="field">
  <label for="f-port">Port</label>
  <input id="f-port" type="number" min="1" max="65535" bind:value={fields.port}
    placeholder={protocol === 'rdp' ? '3389' : protocol === 'ssh' ? '22' : 'domyślny dla protokołu'} />
  {#if fields.port === null && hint('port')}<span class="hint"><Icon name="route" size={12} /> {hint('port')}</span>{/if}
</div>

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
  <div class="field">
    <label for="f-legacy">Starsze algorytmy SSH</label>
    <!-- Trzy stany jak przy Kerberosie: "nie" wyłącza ustawienie odziedziczone z katalogu. -->
    <select id="f-legacy" value={fields.ssh_legacy === null ? 'inherit' : fields.ssh_legacy ? 'yes' : 'no'}
      onchange={(e) => { const v = e.currentTarget.value; fields.ssh_legacy = v === 'inherit' ? null : v === 'yes'; }}>
      <option value="inherit">Dziedzicz{legacyHint ? ` (${legacyHint.value ? 'tak' : 'nie'})` : ' (nie)'}</option>
      <option value="yes">Dopuszczaj</option>
      <option value="no">Nie dopuszczaj</option>
    </select>
    {#if fields.ssh_legacy === null && legacyHint}
      <span class="hint"><Icon name="route" size={12} /> Dziedziczone z „{legacyHint.from}”: {legacyHint.value ? 'tak' : 'nie'}</span>
    {/if}
    <span class="hint">Dla starych serwerów, które nie znają nowych algorytmów i odrzucają połączenie już przy uzgadnianiu. Dopuszcza wymianę kluczy i skróty oparte na SHA-1 oraz szyfry CBC; są słabsze, więc włączaj tylko dla hostów, które inaczej się nie łączą. Serwer znający nowe algorytmy nadal ich użyje.</span>
  </div>
{/if}

{#if protocol !== 'ssh'}
  <div class="field">
    <label for="f-profile">Łącze (RDP)</label>
    <select id="f-profile" value={fields.rdp_profile ?? 'inherit'}
      onchange={(e) => { const v = e.currentTarget.value; fields.rdp_profile = v === 'inherit' ? null : (v as 'fast' | 'slow'); }}>
      <option value="inherit">Dziedzicz ({profileName(profileHint?.value ?? ui.doc?.settings.rdp_profile ?? 'fast')})</option>
      <option value="fast">Szybkie</option>
      <option value="slow">Wolne</option>
    </select>
    {#if fields.rdp_profile === null}
      <span class="hint"><Icon name="route" size={12} />
        {profileHint ? `Dziedziczone z „${profileHint.from}”: ${profileName(profileHint.value)}` : `Z ustawień aplikacji: ${profileName(ui.doc?.settings.rdp_profile ?? 'fast')}`}
      </span>
    {/if}
    <span class="hint">Wolne wyłącza efekty pulpitu (tapetę, animacje, motywy) i wygładzanie czcionek, żeby serwer wysyłał mniej zmian obrazu. Dotyczy nowych połączeń.</span>
  </div>
{/if}
{:else if section === 'terminal'}
{#if protocol !== 'rdp'}
  <div class="field">
    <label for="f-term">Typ terminala (SSH)</label>
    <input id="f-term" type="text" class="mono" list="f-term-list" bind:value={fields.ssh_term} autocomplete="off"
      placeholder={settingsTerm} maxlength="64" />
    <datalist id="f-term-list">
      <option value="xterm-256color"></option>
      <option value="xterm"></option>
      <option value="vt220"></option>
      <option value="vt100"></option>
      <option value="aixterm"></option>
      <option value="ansi"></option>
    </datalist>
    {#if !fields.ssh_term}<span class="hint"><Icon name="route" size={12} /> {hint('ssh_term') ?? `Z ustawień programu: ${settingsTerm}`}</span>{/if}
    <span class="hint">Nazwa wysyłana serwerowi jako TERM. Stary system (np. AIX), który nie zna xterm-256color, zwykle działa z vt100, vt220 albo aixterm; objawem złego typu jest rozsypany ekran i niedziałające klawisze. Dotyczy nowych połączeń.</span>
  </div>
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
  <div class="field">
    <label for="f-font">Rozmiar czcionki terminala (px)</label>
    <input id="f-font" type="number" min="9" max="32" bind:value={fields.terminal_font_size}
      placeholder={String(fontHint?.value ?? settingsFont)} />
    {#if fields.terminal_font_size === null}
      <span class="hint"><Icon name="route" size={12} />
        {fontHint ? `Dziedziczone z „${fontHint.from}”: ${fontHint.value} px` : `Z ustawień programu: ${settingsFont} px`}
      </span>
    {/if}
    <span class="hint">Puste: rozmiar z katalogu albo z ustawień programu. Zmiana działa także w otwartych kartach.</span>
  </div>
  <div class="field">
    <label for="f-login-cmd">Polecenie po zalogowaniu (SSH)</label>
    <input id="f-login-cmd" type="text" class="mono" maxlength="1024" bind:value={fields.ssh_login_command}
      autocomplete="off" spellcheck="false" placeholder="np. tmux new -A -s main" />
    {#if !fields.ssh_login_command && hint('ssh_login_command')}<span class="hint"><Icon name="route" size={12} /> {hint('ssh_login_command')}</span>{/if}
    <span class="hint">Wysyłane do powłoki zaraz po jej otwarciu, zakończone Enterem. Tylko dla hosta docelowego, nie dla bastionów. Dotyczy nowych połączeń.</span>
    <span class="hint"><Icon name="alert" size={12} /> Nie wpisuj tu haseł: polecenie jest zapisane w pliku z hostami i widoczne w tym formularzu.</span>
  </div>
{/if}
{:else if section === 'redirects'}
{#if protocol !== 'ssh'}
  <div class="field">
    <label for="f-webauthn">Klucze bezpieczeństwa FIDO2 (RDP)</label>
    <!-- Trzy stany jak przy Kerberosie: "nie" wyłącza przekierowanie odziedziczone z katalogu. -->
    <select id="f-webauthn" value={fields.rdp_webauthn === null ? 'inherit' : fields.rdp_webauthn ? 'yes' : 'no'}
      onchange={(e) => { const v = e.currentTarget.value; fields.rdp_webauthn = v === 'inherit' ? null : v === 'yes'; }}>
      <option value="inherit">Dziedzicz{webauthnHint ? ` (${webauthnHint.value ? 'tak' : 'nie'})` : ' (nie)'}</option>
      <option value="yes">Przekierowuj</option>
      <option value="no">Nie przekierowuj</option>
    </select>
    {#if fields.rdp_webauthn === null && webauthnHint}
      <span class="hint"><Icon name="route" size={12} /> Dziedziczone z „{webauthnHint.from}”: {webauthnHint.value ? 'tak' : 'nie'}</span>
    {/if}
    <span class="hint">Zdalny pulpit może wtedy prosić o potwierdzenie logowania kluczem (np. YubiKey) podłączonym do tego komputera; każde użycie potwierdzasz w oknie systemu. Włączaj tylko dla zaufanych serwerów. Działa w aplikacji na Windows, dotyczy nowych połączeń.</span>
  </div>
  <div class="field">
    <label for="f-smartcard">Karty inteligentne (RDP)</label>
    <select id="f-smartcard" value={fields.rdp_smartcard ?? 'inherit'}
      onchange={(e) => { const v = e.currentTarget.value; fields.rdp_smartcard = v === 'inherit' ? null : (v as 'off' | 'on' | 'neutral'); }}>
      <option value="inherit">Dziedzicz ({cardName(cardHint?.value)})</option>
      <option value="on">Przekierowuj czytniki</option>
      <option value="neutral">Przekierowuj pod neutralnymi nazwami</option>
      <option value="off">Nie przekierowuj</option>
    </select>
    {#if fields.rdp_smartcard === null && cardHint}
      <span class="hint"><Icon name="route" size={12} /> Dziedziczone z „{cardHint.from}”: {cardName(cardHint.value)}</span>
    {/if}
    <span class="hint">Zdalny pulpit widzi wtedy czytniki kart tego komputera, także klucz sprzętowy z interfejsem kart (np. YubiKey z włączonym CCID). Neutralne nazwy są dla programów, które pomijają czytniki z „YubiKey” w nazwie (KeePassXC). Serwer może wysyłać do karty dowolne polecenia, więc włączaj tylko dla zaufanych serwerów. Działa w aplikacji na Windows, dotyczy nowych połączeń.</span>
  </div>
{/if}
{/if}

<style>
  .link { background: none; border: none; padding: 0; text-decoration: underline; color: var(--text); font-size: 12px; }
</style>
