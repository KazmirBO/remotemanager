// Atrapa backendu Tauri do oglądania interfejsu w zwykłej przeglądarce (`pnpm dev`, /mock.html).
// Dane żyją w pamięci strony. Parametr ?seed=1 wypełnia przykładowe hosty, ?state=locked zaczyna od blokady.
import type { DocView, FieldsIo, FolderView, HostView } from '../lib/api';

type Handler = (args: Record<string, any>, ctx: { headers?: Record<string, string>; raw?: Uint8Array }) => unknown;

const params = new URLSearchParams(location.search);
const callbacks = new Map<number, (m: unknown) => void>();
const listeners = new Map<string, number[]>();
let nextId = 1;
let password: string | null = params.get('state') === 'locked' || params.get('seed') ? 'haslo-testowe' : null;
let unlocked = params.has('seed');

const emptyFields = (): FieldsIo => ({
  port: null, username: null, domain: null, jump_host: null, terminal_scheme: null, rdp_multimon: null, rdp_kerberos: null, rdp_kdc: null, rdp_profile: null, has_password: false,
});
const secrets = new Map<string, string>();
const doc: DocView = { folders: [], hosts: [], settings: { theme: 'dark', terminal_font_size: 13, terminal_scheme: 'domyslny', shortcuts: {}, rdp_profile: 'fast', rdp_keys: 'never' }, trusted_count: 0 };
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
const text = (s: string) => new TextEncoder().encode(s).buffer;

function emitEvent(event: string, payload: unknown) {
  for (const id of listeners.get(event) ?? []) callbacks.get(id)?.({ event, id, payload });
}

const handlers: Record<string, Handler> = {
  vault_state: () => (unlocked ? 'unlocked' : password ? 'locked' : 'missing'),
  create_vault: (a) => {
    if ((a.password as string).length < 8) throw 'Hasło główne musi mieć co najmniej 8 znaków.';
    password = a.password; unlocked = true;
  },
  unlock: (a) => {
    if (a.password !== password) throw 'Nieprawidłowe hasło główne albo uszkodzony plik.';
    unlocked = true;
  },
  lock: () => { unlocked = false; },
  change_password: (a) => {
    if (a.old !== password) throw 'Nieprawidłowe hasło główne albo uszkodzony plik.';
    password = a.new;
  },
  get_doc: () => structuredClone({ ...doc, trusted_count: trusted.size }),
  save_folder: ({ input }) => {
    const id = input.id ?? `f${Date.now()}`;
    const fields = { ...emptyFields(), ...input.fields, has_password: !!input.fields.password || (input.fields.has_password && !input.fields.clear_password) };
    delete (fields as any).password; delete (fields as any).clear_password;
    const existing = doc.folders.find((x) => x.id === id);
    if (existing) Object.assign(existing, { name: input.name, parent: input.parent, fields });
    else doc.folders.push({ id, name: input.name, parent: input.parent, fields });
    return id;
  },
  save_host: ({ input }) => {
    if (!input.name.trim() || !input.address.trim()) throw 'Nazwa i adres hosta są wymagane.';
    const id = input.id ?? `h${Date.now()}`;
    const fields = { ...emptyFields(), ...input.fields, has_password: !!input.fields.password || (input.fields.has_password && !input.fields.clear_password) };
    if (input.fields.password) secrets.set(id, input.fields.password);
    delete (fields as any).password; delete (fields as any).clear_password;
    const existing = doc.hosts.find((x) => x.id === id);
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
  save_settings: ({ settings }) => { doc.settings = settings; },
  answer_trust: ({ accept, remember, id }) => {
    const resolve = pendingTrust.get(id);
    if (resolve) { pendingTrust.delete(id); if (accept && remember) trusted.add('x'); resolve(accept); }
  },
  connect_ssh: async ({ onEvent, hostId, password }) => {
    const host = doc.hosts.find((h) => h.id === hostId)!;
    // Host bez zapisanego hasła i bez agenta: backend prosi o hasło na tę sesję.
    if (host.id === 'h4' && !password) throw 'NEEDS_PASSWORD:Agent SSH jest niedostępny: brak gniazda agenta';
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
    send(text(s === '\r' ? '\r\n$ ' : s));
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
  list_backups: () => [1, 2, 3].map((n) => ({ n, modified: Math.floor(Date.now() / 1000) - n * 3600, size: 2048 + n * 100 })),
  restore_backup: ({ password: pw }) => { if (pw !== password) throw 'Nieprawidłowe hasło dla tej kopii albo uszkodzona kopia.'; },
  get_diagnostics: () => [...diag],
  clear_diagnostics: () => { diag.length = 0; },
  get_local_config: () => ({ log_sessions: logSessions, rdp_clipboard: true, logs_dir: '/home/użytkownik/.local/share/dev.multiremotemanager.app/logs' }),
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
  ssh_close: ({ id }) => { sessions.delete(id); },
  ssh_ack: () => {},
  rdp_grab_keys: () => ({ system: false }),
  rdp_send: () => {},
  rdp_ack: () => {},
  rdp_close: () => {},
  rdp_clipboard_focus: () => {},
};

let syncFolder: string | null = null;
let syncStatus = 'aktualny';
let logSessions = false;
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
