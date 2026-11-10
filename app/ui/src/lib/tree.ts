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

export type InheritableKey = 'port' | 'username' | 'domain' | 'jump_host' | 'terminal_scheme' | 'rdp_multimon';

/**
 * Wartość dziedziczona dla pola, licząc od katalogu `start` w górę.
 * Hasło jest pomijane: frontend zna tylko fakt jego istnienia.
 */
export function inherited(
  folders: FolderView[], start: Id | null, key: InheritableKey,
): { value: NonNullable<FieldsIo[InheritableKey]>; from: string } | null {
  const map = new Map(folders.map((f) => [f.id, f]));
  const seen = new Set<Id>();
  let cur = start ? map.get(start) : undefined;
  while (cur && !seen.has(cur.id)) {
    seen.add(cur.id);
    const v = cur.fields[key];
    if (v !== null && v !== undefined) return { value: v, from: cur.name };
    cur = cur.parent ? map.get(cur.parent) : undefined;
  }
  return null;
}

export function inheritsPassword(folders: FolderView[], start: Id | null): string | null {
  const map = new Map(folders.map((f) => [f.id, f]));
  const seen = new Set<Id>();
  let cur = start ? map.get(start) : undefined;
  while (cur && !seen.has(cur.id)) {
    seen.add(cur.id);
    if (cur.fields.has_password) return cur.name;
    cur = cur.parent ? map.get(cur.parent) : undefined;
  }
  return null;
}
