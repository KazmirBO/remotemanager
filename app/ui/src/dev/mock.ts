// Atrapa backendu Tauri do oglądania interfejsu w zwykłej przeglądarce (`pnpm dev`, /mock.html).
// Dane żyją w pamięci strony. Parametr ?seed=1 wypełnia przykładowe hosty, ?state=locked zaczyna od blokady.
import { defaultSettings, emptyFields, type DocView, type FieldsIo, type FolderView, type HostView, type Settings } from '../lib/api';

type Handler = (args: Record<string, any>, ctx: { headers?: Record<string, string>; raw?: Uint8Array }) => unknown;

const params = new URLSearchParams(location.search);
const callbacks = new Map<number, (m: unknown) => void>();
const listeners = new Map<string, number[]>();
let nextId = 1;
let password: string | null = params.get('state') === 'locked' || params.get('seed') ? 'haslo-testowe' : null;
let unlocked = params.has('seed');

const secrets = new Map<string, string>();

/** Jak backend: import klucza przy zapisie (hasło klucza w atrapie to `haslo-klucza`). */
function importKey(input: any, existing: FieldsIo | undefined) {
  const text: string = (input.ssh_key ?? '').trim();
  let imported = false;
  if (text) {
    if (!text.includes('PRIVATE KEY')) throw 'KEY_INVALID:Nie można odczytać klucza: brak nagłówka';
    if (text.includes('ENCRYPTED')) {
      const pass = input.ssh_key_passphrase ?? '';
      if (!pass) throw 'KEY_NEEDS_PASSPHRASE:Klucz jest zaszyfrowany. Podaj hasło klucza, aby go zaimportować.';
      if (pass !== 'haslo-klucza') throw 'KEY_BAD_PASSPHRASE:Nieprawidłowe hasło klucza.';
    }
    imported = true;
  }
  const keep = !input.clear_ssh_key && (imported || !!existing?.has_ssh_key);
  return {
    has_ssh_key: keep,
    ssh_key_algorithm: keep ? 'ssh-ed25519' : null,
    ssh_key_fingerprint: keep ? 'SHA256:mockkey000000000000000000000000000000000000' : null,
  };
}
const FONT_ERROR = 'Rozmiar czcionki terminala musi być liczbą od 9 do 32.';
const COMMAND_ERROR = 'Polecenie po zalogowaniu może mieć najwyżej 1024 znaki i nie może zawierać znaków sterujących poza tabulatorem.';
/** Jak `FieldsIo::prepare` w backendzie: zakresy i przycięcie polecenia (RDP zeruje pola terminala). */
function checkTerminalFields(f: any, rdp: boolean) {
  if (rdp) { f.terminal_font_size = null; f.ssh_login_command = null; return; }
  const size = f.terminal_font_size;
  if (size !== null && size !== undefined && !(Number.isInteger(size) && size >= 9 && size <= 32)) throw FONT_ERROR;
  const cmd = typeof f.ssh_login_command === 'string' ? f.ssh_login_command.trim() : '';
  if (!cmd) f.ssh_login_command = null;
  else {
    // eslint-disable-next-line no-control-regex
    if ([...cmd].length > 1024 || /[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/.test(cmd)) throw COMMAND_ERROR;
    f.ssh_login_command = cmd;
  }
}
/** Jak `validate_settings` w backendzie (teksty błędów identyczne). */
function checkSettings(s: Settings) {
  if (!(s.terminal_font_size >= 9 && s.terminal_font_size <= 32)) throw FONT_ERROR;
  if (!/^[A-Za-z0-9_.+-]{1,64}$/.test(s.ssh_term)) throw 'Domyślny typ terminala może mieć najwyżej 64 znaki: litery, cyfry oraz - _ . + (np. xterm-256color).';
  if (!(s.terminal_scrollback >= 0 && s.terminal_scrollback <= 100_000)) throw 'Historia przewijania musi być liczbą od 0 do 100000 wierszy.';
  if (!(s.ssh_keepalive_secs >= 0 && s.ssh_keepalive_secs <= 3600)) throw 'Odstęp podtrzymywania połączenia SSH musi być liczbą od 0 do 3600 sekund.';
  if (!(s.auto_lock_minutes >= 0 && s.auto_lock_minutes <= 1440)) throw 'Czas automatycznej blokady musi być liczbą od 0 do 1440 minut.';
}
const stripInputs = (f: any) => {
  delete f.password; delete f.clear_password; delete f.ssh_key; delete f.ssh_key_passphrase; delete f.clear_ssh_key;
};
const doc: DocView = { folders: [], hosts: [], settings: { ...defaultSettings(), theme: 'dark' }, trusted_count: 0, mfa: { totp: false, recovery_left: 0 } };
// `?totp=1` zaczyna z włączonymi kodami jednorazowymi (dobry kod w atrapie to 123456).
let totp = params.has('totp');
let recoveryCodes: string[] = totp ? ['AAAQE-AYEAU', 'BBBRF-BZFBV'] : [];
let pendingCode = false;
let codeFailures = 0;
let enrolling = false;
const trusted = new Set<string>();

function seed() {
  const f = (id: string, name: string, parent: string | null, fields: Partial<FieldsIo> = {}): FolderView => ({
    id, name, parent, fields: { ...emptyFields(), ...fields },
  });
  doc.folders = [
    f('f1', 'Firma', null, { username: 'admin', port: 2222 }),
    f('f2', 'Produkcja', 'f1', { domain: 'FIRMA' }),
    f('f3', 'Laboratorium', null),
  ];
  const h = (id: string, name: string, address: string, protocol: 'ssh' | 'rdp', folder: string | null, favorite = false): HostView => ({
    id, name, address, protocol, folder, favorite, notes: '', fields: emptyFields(),
  });
  doc.hosts = [
    h('h1', 'bastion', 'bastion.firma.example', 'ssh', 'f1', true),
    h('h2', 'db-01', '10.0.5.21', 'ssh', 'f2'),
    h('h3', 'dc01', 'dc01.firma.example', 'rdp', 'f2'),
    h('h4', 'raspberry', '192.168.1.50', 'ssh', null, true),
  ];
}
if (params.has('seed')) seed();

function nextIndexSender(callbackId: number) {
  let index = 0;
  return (message: unknown) => callbacks.get(callbackId)?.({ index: index++, message });
}

const sessions = new Map<string, (m: unknown) => void>();
/** Wpisywana linia w sesji SSH atrapy; `exit` kończy sesję jak prawdziwa powłoka. */
const typed = new Map<string, string>();
const text = (s: string) => new TextEncoder().encode(s).buffer;

function emitEvent(event: string, payload: unknown) {
  for (const id of listeners.get(event) ?? []) callbacks.get(id)?.({ event, id, payload });
}

const IMPORT_PARTS = {
  usernames: true, passwords: false, ssh_keys: false, key_paths: false, options: true, login_command: false, notes: true, trusted_keys: true,
};
/** Jak `open_package` w backendzie: limit rozmiaru, a potem znacznik pliku i hasło albo nagłówek CSV. */
function openImport(data: number[], pw: string, format: string | undefined) {
  if (data.length > 4 * 1024 * 1024) throw 'Plik jest za duży na plik importu hostów (limit 4 MiB).';
  if (format === 'csv') {
    const header = new TextDecoder().decode(new Uint8Array(data)).split('\n')[0].toLowerCase();
    for (const col of ['nazwa', 'adres', 'protokol']) {
      if (!header.includes(col)) throw `Nie można odczytać pliku CSV: brak kolumny ${col} w nagłówku (wymagane: nazwa, adres, protokol; opcjonalnie: katalog).`;
    }
    return;
  }
  if (String.fromCharCode(...data.slice(0, 4)) !== 'MRMX') throw 'To nie jest plik eksportu hostów.';
  if (pw !== 'haslo-pliku') throw 'Nieprawidłowe hasło pliku eksportu albo plik jest uszkodzony.';
}
/** Lista CSV nie niesie żadnej kategorii danych. */
const NO_PARTS = Object.fromEntries(Object.keys(IMPORT_PARTS).map((k) => [k, false]));

const handlers: Record<string, Handler> = {
  vault_state: () => (unlocked ? 'unlocked' : password ? 'locked' : 'missing'),
  create_vault: (a) => {
    if ((a.password as string).length < 8) throw 'Hasło główne musi mieć co najmniej 8 znaków.';
    password = a.password; unlocked = true;
  },
  unlock: (a) => {
    if (a.password !== password) throw 'Nieprawidłowe hasło główne albo uszkodzony plik.';
    if (totp) { pendingCode = true; codeFailures = 0; throw 'NEEDS_TOTP:Podaj kod z aplikacji uwierzytelniającej.'; }
    unlocked = true;
  },
  // Kody jednorazowe: w atrapie dobry kod to zawsze 123456, a kody zapasowe są stałe.
  unlock_totp: ({ code }) => {
    if (!pendingCode) throw 'Najpierw podaj hasło główne.';
    const text = String(code).replace(/[\s-]/g, '').toUpperCase();
    const backup = recoveryCodes.findIndex((c) => c.replace('-', '') === text);
    if (text !== '123456' && backup < 0) {
      codeFailures += 1;
      if (codeFailures >= 5) { pendingCode = false; throw 'TOTP_EXPIRED:Za dużo błędnych kodów. Podaj hasło główne ponownie.'; }
      throw 'TOTP_BAD:Nieprawidłowy kod. Sprawdź, czy zegar telefonu jest dobrze ustawiony.';
    }
    if (backup >= 0) recoveryCodes.splice(backup, 1);
    pendingCode = false;
    unlocked = true;
  },
  totp_begin: () => {
    if (totp) throw 'Kody jednorazowe są już włączone.';
    enrolling = true;
    return {
      secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      uri: 'otpauth://totp/Mened%C5%BCer%20sesji:plik%20z%20hostami?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Mened%C5%BCer%20sesji&algorithm=SHA1&digits=6&period=30',
    };
  },
  totp_enable: ({ code }) => {
    if (!enrolling) throw 'Zacznij włączanie od nowa: sekret wygasł.';
    if (String(code).replace(/\s/g, '') !== '123456') throw 'Nieprawidłowy kod. Wpisz bieżący kod z aplikacji uwierzytelniającej.';
    enrolling = false;
    totp = true;
    recoveryCodes = ['AAAQE-AYEAU', 'BBBRF-BZFBV', 'CCCSG-CAGCW', 'DDDTH-DBHDX', 'EEEUI-ECIEY', 'FFFVJ-FDJFZ', 'GGGWK-GEKG2', 'HHHXL-HFLH3'];
    return [...recoveryCodes];
  },
  totp_disable: ({ code }) => {
    if (!totp) throw 'Kody jednorazowe nie są włączone.';
    const text = String(code).replace(/[\s-]/g, '').toUpperCase();
    if (text !== '123456' && !recoveryCodes.some((c) => c.replace('-', '') === text)) throw 'Nieprawidłowy kod.';
    totp = false;
    recoveryCodes = [];
  },
  lock: () => { unlocked = false; },
  change_password: (a) => {
    if (a.old !== password) throw 'Nieprawidłowe hasło główne albo uszkodzony plik.';
    password = a.new;
  },
  get_doc: () => structuredClone({ ...doc, trusted_count: trusted.size, mfa: { totp, recovery_left: recoveryCodes.length } }),
  save_folder: ({ input }) => {
    if (!input.name.trim()) throw 'Nazwa katalogu nie może być pusta.';
    checkTerminalFields(input.fields, false);
    const id = input.id ?? `f${Date.now()}`;
    const existing = doc.folders.find((x) => x.id === id);
    const key = importKey(input.fields, existing?.fields);
    const fields = { ...emptyFields(), ...input.fields, ...key, has_password: !!input.fields.password || (input.fields.has_password && !input.fields.clear_password) };
    stripInputs(fields);
    if (existing) Object.assign(existing, { name: input.name, parent: input.parent, fields });
    else doc.folders.push({ id, name: input.name, parent: input.parent, fields });
    return id;
  },
  save_host: ({ input }) => {
    if (!input.name.trim() || !input.address.trim()) throw 'Nazwa i adres hosta są wymagane.';
    checkTerminalFields(input.fields, input.protocol === 'rdp');
    const id = input.id ?? `h${Date.now()}`;
    const existing = doc.hosts.find((x) => x.id === id);
    const key = importKey(input.fields, existing?.fields);
    const fields = { ...emptyFields(), ...input.fields, ...key, has_password: !!input.fields.password || (input.fields.has_password && !input.fields.clear_password) };
    if (input.fields.password) secrets.set(id, input.fields.password);
    stripInputs(fields);
    const body = { name: input.name, address: input.address, protocol: input.protocol, folder: input.folder, notes: input.notes, fields };
    if (existing) Object.assign(existing, body);
    else doc.hosts.push({ id, favorite: false, ...body });
    return id;
  },
  delete_folder: ({ id }) => {
    const gone = new Set([id]);
    for (let grew = true; grew;) {
      grew = false;
      for (const f of doc.folders) if (f.parent && gone.has(f.parent) && !gone.has(f.id)) { gone.add(f.id); grew = true; }
    }
    const n = doc.hosts.filter((h) => h.folder && gone.has(h.folder)).length;
    doc.folders = doc.folders.filter((f) => !gone.has(f.id));
    doc.hosts = doc.hosts.filter((h) => !(h.folder && gone.has(h.folder)));
    return n;
  },
  delete_host: ({ id }) => { doc.hosts = doc.hosts.filter((h) => h.id !== id); },
  move_host: ({ id, folder }) => { doc.hosts.find((h) => h.id === id)!.folder = folder; },
  move_folder: ({ id, parent }) => {
    // Jak backend: katalogu nie da się przenieść do samego siebie ani do potomka.
    for (let p = parent; p; p = doc.folders.find((f) => f.id === p)?.parent ?? null) {
      if (p === id) throw 'przeniesienie utworzyłoby cykl katalogów';
    }
    doc.folders.find((f) => f.id === id)!.parent = parent;
  },
  set_favorite: ({ id, favorite }) => { doc.hosts.find((h) => h.id === id)!.favorite = favorite; },
  save_settings: ({ settings }) => { checkSettings(settings); doc.settings = settings; },
  answer_trust: ({ accept, remember, id }) => {
    const resolve = pendingTrust.get(id);
    if (resolve) { pendingTrust.delete(id); if (accept && remember) trusted.add('x'); resolve(accept); }
  },
  connect_ssh: async ({ onEvent, hostId, password, keyPassphrase }) => {
    const host = doc.hosts.find((h) => h.id === hostId)!;
    // Klucz ze ścieżki zakończonej na `_enc` jest zaszyfrowany (hasło: haslo-klucza).
    const path = host.fields.ssh_key_path;
    if (path?.endsWith('_enc')) {
      if (!keyPassphrase) throw `NEEDS_KEY_PASSPHRASE:Klucz ${path} jest zaszyfrowany. Podaj jego hasło.`;
      if (keyPassphrase !== 'haslo-klucza') throw `NEEDS_KEY_PASSPHRASE:Nieprawidłowe hasło klucza ${path}. Spróbuj ponownie.`;
    }
    // Host bez zapisanego hasła, klucza i agenta: backend prosi o hasło na tę sesję.
    if (host.id === 'h4' && !password && !secrets.has(host.id) && !path && !host.fields.has_ssh_key) throw 'NEEDS_PASSWORD:Agent SSH jest niedostępny: brak gniazda agenta';
    const send = nextIndexSender(onEvent.id);
    if (!trusted.has(host.address)) {
      const ok = await askTrust({ protocol: 'ssh', host: host.address, port: 22, algorithm: 'ssh-ed25519', fingerprint: 'SHA256:mock0000000000000000000000000000000000000000' });
      if (!ok) throw `klucz hosta ${host.address}:22 został odrzucony`;
      trusted.add(host.address);
    }
    const id = crypto.randomUUID();
    sessions.set(id, send);
    setTimeout(() => send(text(`Połączono z ${host.address} (atrapa)\r\n$ `)), 50);
    return id;
  },
  connect_rdp: async ({ onEvent, hostId, password }) => {
    if (!secrets.has(hostId) && !password) throw 'NEEDS_PASSWORD:Host nie ma zapisanego hasła, a RDP z NLA go wymaga.';
    const send = nextIndexSender(onEvent.id);
    const id = crypto.randomUUID();
    setTimeout(() => {
      const w = 640, h = 400;
      send({ t: 'connected', width: w, height: h });
      const buf = new ArrayBuffer(8 + w * h * 4);
      const view = new DataView(buf);
      [0, 0, w, h].forEach((v, i) => view.setUint16(i * 2, v, true));
      const px = new Uint8Array(buf, 8);
      for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
        const o = (y * w + x) * 4;
        px[o] = (x * 255) / w; px[o + 1] = (y * 255) / h; px[o + 2] = 120; px[o + 3] = 255;
      }
      send(buf);
    }, 300);
    return id;
  },
  ssh_write: (_a, ctx) => {
    const id = ctx.headers?.['x-session'];
    const send = id ? sessions.get(id) : undefined;
    if (!send || !ctx.raw) return;
    const s = new TextDecoder().decode(ctx.raw);
    if (s !== '\r') {
      typed.set(id!, (typed.get(id!) ?? '') + s);
      send(text(s));
      return;
    }
    const line = typed.get(id!) ?? '';
    typed.delete(id!);
    if (line.trim() === 'exit') {
      send(text('\r\nwylogowano\r\n'));
      send({ t: 'exit', code: 0 });
      sessions.delete(id!);
      return;
    }
    send(text('\r\n$ '));
  },
  sync_status: () => syncView(),
  sync_set_folder: ({ folder }) => { syncFolder = folder; syncStatus = 'brak_pliku'; return syncView(); },
  sync_run: ({ keep }) => {
    if (syncStatus === 'konflikt' && !keep) throw 'Konflikt: wybierz, którą wersję zachować.';
    const locked = syncStatus === 'zdalne_zmiany' || keep === 'remote';
    syncStatus = 'aktualny';
    if (locked) unlocked = false;
    diag.push(`${Math.floor(Date.now() / 1000)} synchronizacja (atrapa)`);
    return { view: syncView(), locked };
  },
  // Różnice do oglądania: stała próbka; `?sync_diff=other` udaje plik z innym hasłem głównym.
  sync_diff: () => {
    if (!syncFolder) throw 'Synchronizacja nie jest skonfigurowana.';
    if (syncStatus === 'brak_pliku') throw 'W folderze synchronizacji nie ma jeszcze pliku z hostami.';
    if (params.get('sync_diff') === 'other') return { readable: false, diff: null };
    const empty = { folders: [], hosts: [], defaults: [], trusted_local_only: 0, trusted_remote_only: 0, settings_differ: false, mfa_differ: false };
    if (syncStatus === 'aktualny') return { readable: true, diff: empty };
    const item = (id: string, name: string, path: string, address: string | null, protocol: string | null, side: string, changes: unknown[] = []) =>
      ({ id, name, path, address, protocol, side, changes });
    return {
      readable: true,
      diff: {
        ...empty,
        folders: [item('d-f1', 'Test', 'Firma', null, null, 'remote_only')],
        hosts: [
          item('h4', 'raspberry', '', '192.168.1.50', 'ssh', 'local_only'),
          item('d-h1', 'web-03', 'Firma / Test', '10.0.7.13', 'ssh', 'remote_only'),
          item('d-h2', 'term-01', 'Firma / Test', 'term-01.firma.example', 'rdp', 'remote_only'),
          item('h2', 'db-01', 'Firma / Produkcja', '10.0.5.21', 'ssh', 'changed', [
            { kind: 'address', local: '10.0.5.21', remote: '10.0.5.121' },
            { kind: 'location', local: 'Firma / Produkcja', remote: '' },
            { kind: 'part', part: 'passwords' },
            { kind: 'part', part: 'options' },
          ]),
          item('h3', 'dc01', 'Firma / Produkcja', 'dc01.firma.example', 'rdp', 'changed', [
            { kind: 'name', local: 'dc01', remote: 'dc01-stary' },
            { kind: 'notes' },
          ]),
        ],
        defaults: ['options'],
        trusted_local_only: 1,
        trusted_remote_only: 2,
        settings_differ: true,
      },
    };
  },
  list_backups: () => [1, 2, 3].map((n) => ({ n, modified: Math.floor(Date.now() / 1000) - n * 3600, size: 2048 + n * 100 })),
  restore_backup: ({ password: pw }) => { if (pw !== password) throw 'Nieprawidłowe hasło dla tej kopii albo uszkodzona kopia.'; },
  // Eksport i import: atrapa nie szyfruje. Eksport tylko liczy elementy, a import przyjmuje każdy
  // plik zaczynający się od "MRMX" z hasłem `haslo-pliku` i zwraca stałą paczkę: jeden istniejący
  // host (h2) z nową nazwą oraz nowy katalog z dwoma hostami.
  export_default_path: () => '/home/użytkownik/Pobrane/hosty-2026-11-20.mrmx',
  export_hosts: ({ path, password: pw, parts, folder }) => {
    if ([...(pw as string)].length < 8) throw 'Hasło pliku eksportu musi mieć co najmniej 8 znaków.';
    const target = (path as string).trim();
    if (!target.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(target)) throw 'Ścieżka pliku eksportu musi być bezwzględna.';
    if (target.includes('istnieje')) throw 'Plik o tej nazwie już istnieje. Podaj inną nazwę.';
    let inside: Set<string> | null = null;
    if (folder) {
      inside = new Set<string>([folder]);
      for (let grew = true; grew;) {
        grew = false;
        for (const f of doc.folders) if (f.parent && inside.has(f.parent) && !inside.has(f.id)) { inside.add(f.id); grew = true; }
      }
    }
    const folders = doc.folders.filter((f) => !inside || inside.has(f.id)).length;
    const hosts = doc.hosts.filter((h) => !inside || (h.folder !== null && inside.has(h.folder))).length;
    if (!folders && !hosts) throw 'Nie ma czego eksportować: lista hostów jest pusta.';
    diag.push(`${Math.floor(Date.now() / 1000)} eksport: zapisano ${hosts} hostów i ${folders} katalogów (atrapa)`);
    return { path: /\.mrmx$/i.test(target) ? target : `${target}.mrmx`, folders, hosts, trusted_keys: parts.trusted_keys ? trusted.size : 0 };
  },
  import_preview: ({ data, password: pw, format }) => {
    openImport(data, pw, format);
    const existing = doc.hosts.some((h) => h.id === 'h2') ? 1 : 0;
    const added = doc.hosts.some((h) => h.id === 'imp-h1');
    return {
      parts: format === 'csv' ? NO_PARTS : IMPORT_PARTS,
      folders_new: added ? 0 : 1, folders_existing: added ? 1 : 0,
      hosts_new: added ? 0 : 2 + (1 - existing), hosts_existing: added ? 3 : existing,
      trusted_new: format === 'csv' || trusted.has('import') ? 0 : 1,
    };
  },
  import_hosts: ({ data, password: pw, format, parts: chosen, existing }) => {
    openImport(data, pw, format);
    const parts = format === 'csv' ? NO_PARTS : chosen;
    const report = { folders_added: 0, folders_updated: 0, hosts_added: 0, hosts_updated: 0, unchanged: 0, trusted_added: 0, trusted_conflicts: 0, jumps_dropped: 0 };
    if (doc.folders.some((f) => f.id === 'imp-f1')) report.unchanged += 1;
    else { doc.folders.push({ id: 'imp-f1', name: 'Z importu', parent: null, fields: emptyFields() }); report.folders_added += 1; }
    for (const [id, name, address] of [['imp-h1', 'web-01', '10.0.7.11'], ['imp-h2', 'web-02', '10.0.7.12']]) {
      if (doc.hosts.some((h) => h.id === id)) { report.unchanged += 1; continue; }
      doc.hosts.push({
        id, name, address, protocol: 'ssh', folder: 'imp-f1', favorite: false, notes: parts.notes ? 'z pliku' : '',
        fields: { ...emptyFields(), username: parts.usernames ? 'deploy' : null },
      });
      report.hosts_added += 1;
    }
    const h2 = doc.hosts.find((h) => h.id === 'h2');
    if (h2 && existing === 'update' && h2.name !== 'db-01 (z pliku)') {
      h2.name = 'db-01 (z pliku)';
      if (parts.usernames) h2.fields.username = 'postgres';
      report.hosts_updated += 1;
    } else if (h2) report.unchanged += 1;
    if (parts.trusted_keys && !trusted.has('import')) { trusted.add('import'); report.trusted_added += 1; }
    return report;
  },
  get_diagnostics: () => [...diag],
  clear_diagnostics: () => { diag.length = 0; },
  get_local_config: () => ({ log_sessions: logSessions, rdp_clipboard: true, logs_dir: '/home/użytkownik/.local/share/dev.multiremotemanager.app/logs', backup_count: backupCount, check_updates: checkUpdates }),
  set_check_updates: ({ enabled }) => { checkUpdates = enabled; },
  open_releases_page: () => {
    if (params.get('update') === 'nobrowser') throw 'Nie udało się otworzyć przeglądarki. Adres strony wydań: https://github.com/KazmirBO/remotemanager/releases';
    diag.push(`${Math.floor(Date.now() / 1000)} otwarto stronę wydań (atrapa)`);
  },
  // Wersja programu dla sprawdzania wydań; bez `?update=...` atrapa nie pyta sieci.
  'plugin:app|version': () => params.get('version') ?? '0.1.0',
  set_backup_count: ({ count }) => {
    if (!Number.isInteger(count) || count < 1 || count > 20) throw 'Liczba kopii zapasowych musi być liczbą od 1 do 20.';
    backupCount = count;
    diag.push(`${Math.floor(Date.now() / 1000)} kopie zapasowe: limit ${count} (atrapa)`);
  },
  user_activity: () => {},
  answer_quit: ({ quit }) => { if (quit) diag.push(`${Math.floor(Date.now() / 1000)} zakończenie programu (atrapa)`); },
  read_clipboard_text: () => 'tekst ze schowka (atrapa)',
  set_rdp_clipboard: () => {},
  set_log_sessions: ({ enabled }) => { logSessions = enabled; },
  resolve_link: ({ url }) => {
    const m = /^(ssh|rdp):\/\/(?:([^@/]+)@)?([^:/?]+)(?::(\d+))?/i.exec(url);
    if (!m) throw 'Nieprawidłowy link: nieobsługiwany schemat (oczekiwano ssh:// albo rdp://).';
    const host = doc.hosts.find((h) => h.protocol === m[1].toLowerCase() && h.address === m[3]);
    const port = m[4] ? Number(m[4]) : null;
    const resolved_port = port ?? (m[1].toLowerCase() === 'rdp' ? 3389 : 22);
    return { protocol: m[1].toLowerCase(), host: m[3], port, resolved_port, username: m[2] ?? null, domain: null, matching_host: host?.id ?? null };
  },
  take_pending_link: () => params.get('link'),
  ssh_resize: () => {},
  ssh_close: ({ id }) => { sessions.delete(id); typed.delete(id); },
  ssh_ack: () => {},
  rdp_grab_keys: () => ({ system: false }),
  rdp_send: () => {},
  rdp_ack: () => {},
  rdp_close: () => {},
  rdp_clipboard_focus: () => {},
};

// `?sync=konflikt` (albo zdalne_zmiany, lokalne_zmiany) zaczyna od skonfigurowanej synchronizacji w tym stanie.
let syncFolder: string | null = params.get('sync') ? '/home/użytkownik/Synchronizacja' : null;
let syncStatus = params.get('sync') ?? 'aktualny';
let logSessions = false;
let backupCount = 5;
// `?update=1` włącza w atrapie sprawdzanie nowej wersji (odpowiedź GitHuba podstawia test).
let checkUpdates = params.has('update');
const diag: string[] = [`${Math.floor(Date.now() / 1000)} odblokowano plik z hostami (atrapa)`];
const syncView = () => ({ folder: syncFolder, status: syncFolder ? syncStatus : null, error: null });

const pendingTrust = new Map<string, (ok: boolean) => void>();
function askTrust(info: { protocol: string; host: string; port: number; algorithm: string; fingerprint: string }) {
  const id = crypto.randomUUID();
  return new Promise<boolean>((resolve) => {
    pendingTrust.set(id, resolve);
    emitEvent('trust-request', { id, previous: null, ...info });
  });
}

/** Ręczna próba pytania o zamknięcie programu: w konsoli `mockQuit()`. */
(globalThis as any).mockQuit = () => emitEvent('quit-requested', { sessions: sessions.size });

(window as any).__TAURI_INTERNALS__ = {
  transformCallback(cb: (m: unknown) => void) {
    const id = nextId++;
    callbacks.set(id, cb);
    return id;
  },
  unregisterCallback(id: number) { callbacks.delete(id); },
  convertFileSrc: (p: string) => p,
  async invoke(cmd: string, args: any, options?: { headers?: Record<string, string> }) {
    if (cmd === 'plugin:event|listen') {
      const list = listeners.get(args.event) ?? [];
      list.push(args.handler);
      listeners.set(args.event, list);
      return args.handler;
    }
    if (cmd.startsWith('plugin:event|')) return;
    const h = handlers[cmd];
    if (!h) throw `atrapa: nieznane polecenie ${cmd}`;
    const raw = args instanceof Uint8Array ? args : undefined;
    return h(raw ? {} : args ?? {}, { headers: options?.headers, raw });
  },
};
(window as any).__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };

await import('../main');
