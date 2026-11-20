import type { FieldsIo, FolderView, HostView, Id } from './api';

export interface FolderNode {
  folder: FolderView;
  folders: FolderNode[];
  hosts: HostView[];
}

const byName = <T extends { name: string }>(a: T, b: T) => a.name.localeCompare(b.name, 'pl');

/** Buduje drzewo z płaskich list; elementy z uszkodzonym rodzicem trafiają do korzenia. */
export function buildTree(folders: FolderView[], hosts: HostView[]): { roots: FolderNode[]; rootHosts: HostView[] } {
  const nodes = new Map<Id, FolderNode>(folders.map((f) => [f.id, { folder: f, folders: [], hosts: [] }]));
  const roots: FolderNode[] = [];
  for (const n of nodes.values()) {
    const parent = n.folder.parent ? nodes.get(n.folder.parent) : undefined;
    (parent ? parent.folders : roots).push(n);
  }
  const rootHosts: HostView[] = [];
  for (const h of hosts) {
    const parent = h.folder ? nodes.get(h.folder) : undefined;
    (parent ? parent.hosts : rootHosts).push(h);
  }
  const sort = (list: FolderNode[]) => {
    list.sort((a, b) => byName(a.folder, b.folder));
    for (const n of list) {
      n.hosts.sort(byName);
      sort(n.folders);
    }
  };
  sort(roots);
  rootHosts.sort(byName);
  return { roots, rootHosts };
}

/** Identyfikatory katalogu i wszystkich jego potomków (do blokowania przenoszenia w siebie). */
export function descendantIds(folders: FolderView[], id: Id): Set<Id> {
  const out = new Set<Id>([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const f of folders) {
      if (f.parent && out.has(f.parent) && !out.has(f.id)) {
        out.add(f.id);
        grew = true;
      }
    }
  }
  return out;
}

export function matches(h: HostView, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [h.name, h.address, h.notes].some((s) => s.toLowerCase().includes(q));
}

export type InheritableKey =
  | 'port' | 'username' | 'domain' | 'jump_host' | 'terminal_scheme' | 'rdp_multimon' | 'rdp_kerberos' | 'rdp_kdc' | 'rdp_profile' | 'rdp_webauthn' | 'rdp_smartcard' | 'ssh_key_path' | 'ssh_term' | 'ssh_legacy' | 'terminal_font_size' | 'ssh_login_command';

/**
 * Wartość dziedziczona dla pola, licząc od katalogu `start` w górę.
 * Hasło jest pomijane: frontend zna tylko fakt jego istnienia.
 * Poziom z wartością `skip` jest pomijany i dziedziczenie idzie dalej (bastion wskazujący sam
 * edytowany host, tak jak w `Tree::resolve` po stronie backendu).
 */
export function inherited(
  folders: FolderView[], start: Id | null, key: InheritableKey, skip?: FieldsIo[InheritableKey],
): { value: NonNullable<FieldsIo[InheritableKey]>; from: string } | null {
  return firstUp(folders, start, (f) => {
    const v = f.fields[key];
    return v !== null && v !== undefined && v !== skip ? { value: v, from: f.name } : null;
  });
}

/** Pierwszy niepusty wynik `pick` idąc od katalogu `start` w górę; pętla w drzewie kończy wędrówkę. */
function firstUp<T>(folders: FolderView[], start: Id | null, pick: (f: FolderView) => T | null): T | null {
  const map = new Map(folders.map((f) => [f.id, f]));
  const seen = new Set<Id>();
  let cur = start ? map.get(start) : undefined;
  while (cur && !seen.has(cur.id)) {
    seen.add(cur.id);
    const v = pick(cur);
    if (v !== null) return v;
    cur = cur.parent ? map.get(cur.parent) : undefined;
  }
  return null;
}

export function inheritsPassword(folders: FolderView[], start: Id | null): string | null {
  return firstUp(folders, start, (f) => (f.fields.has_password ? f.name : null));
}

/** Pierwszy katalog w górę (od `start`), który ma zapisany klucz SSH w pliku hostów. */
export function inheritsSshKey(
  folders: FolderView[], start: Id | null,
): { from: string; algorithm: string; fingerprint: string } | null {
  return firstUp(folders, start, (f) =>
    f.fields.has_ssh_key
      ? { from: f.name, algorithm: f.fields.ssh_key_algorithm ?? '', fingerprint: f.fields.ssh_key_fingerprint ?? '' }
      : null);
}

/** Odmiana rzeczownika po liczbie: `one` dla 1, `few` dla 2-4 (poza 12-14), `many` w pozostałych. */
export function plural(n: number, one: string, few: string, many: string): string {
  if (n === 1) return one;
  const t = n % 10, h = n % 100;
  return t >= 2 && t <= 4 && (h < 12 || h > 14) ? few : many;
}

/** Strefa przy krawędzi listy (w pikselach), w której przeciągany element przewija listę. */
export const EDGE_SCROLL_ZONE = 40;
/** Największy krok przewijania na klatkę (w pikselach), tuż przy krawędzi. */
export const EDGE_SCROLL_MAX = 14;

/** Krok przewijania listy na klatkę dla wskaźnika na wysokości `y` podczas przeciągania: ujemny przy
 * górnej krawędzi, dodatni przy dolnej, zero w środku. Im bliżej krawędzi, tym szybciej; wskaźnik
 * poza listą przewija z największą prędkością. */
export function edgeScrollSpeed(y: number, top: number, bottom: number): number {
  const speed = (distance: number) =>
    Math.ceil(((EDGE_SCROLL_ZONE - Math.max(0, distance)) / EDGE_SCROLL_ZONE) * EDGE_SCROLL_MAX);
  // Lista niższa od dwóch stref: przewija tylko połowa bliższa danej krawędzi.
  const zone = Math.min(EDGE_SCROLL_ZONE, (bottom - top) / 2);
  if (y - top < zone) return -speed(y - top);
  if (bottom - y < zone) return speed(bottom - y);
  return 0;
}
