// Sprawdzanie, czy na GitHubie jest nowsze wydanie programu. Tylko informacja: niczego nie pobiera.

/** Lista wydań w API GitHuba (repozytorium jest publiczne, więc bez uwierzytelnienia). */
export const RELEASES_API = 'https://api.github.com/repos/KazmirBO/remotemanager/releases?per_page=30';
/** Strona wydań dla człowieka; ten sam adres otwiera backend (`open_releases_page`). */
export const RELEASES_URL = 'https://github.com/KazmirBO/remotemanager/releases';

export interface Release { tag_name: string; prerelease: boolean; draft: boolean }
interface Version { core: [number, number, number]; pre: string[] }

/** Rozkłada numer `1.2.3` albo `1.2.3-rc1` (także z `v` na początku); inne napisy dają null. */
export function parseVersion(text: string): Version | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(text.trim());
  if (!m) return null;
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split('.') : [] };
}

/**
 * Porządek wersji jak w SemVer: liczba ujemna, gdy `a` jest starsze. Wydanie wstępne jest starsze
 * od wydania o tym samym numerze; człony przyrostka porównuje się kolejno, liczbowe jako liczby,
 * a liczbowe przed tekstowymi.
 */
export function compareVersions(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) if (a.core[i] !== b.core[i]) return a.core[i] - b.core[i];
  if (!a.pre.length || !b.pre.length) return (a.pre.length ? 0 : 1) - (b.pre.length ? 0 : 1);
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i], y = b.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) return Number(x) - Number(y);
    if (nx !== ny) return nx ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Najnowsze wydanie nowsze od używanej wersji albo null. Wydania wstępne liczą się tylko dla kogoś,
 * kto sam używa wydania wstępnego; szkice i tagi, które nie są numerem wersji, są pomijane.
 */
export function newerVersion(current: string, releases: Release[]): string | null {
  const mine = parseVersion(current);
  if (!mine) return null;
  const wantPre = mine.pre.length > 0;
  let best: { text: string; v: Version } | null = null;
  for (const r of releases) {
    if (!r || r.draft || typeof r.tag_name !== 'string') continue;
    if (r.prerelease && !wantPre) continue;
    const v = parseVersion(r.tag_name);
    if (!v || (v.pre.length > 0 && !wantPre)) continue;
    if (compareVersions(v, mine) <= 0) continue;
    if (!best || compareVersions(v, best.v) > 0) best = { text: r.tag_name.replace(/^v/, ''), v };
  }
  return best?.text ?? null;
}

/** Pyta GitHuba o wydania i zwraca numer nowszej wersji albo null. Błąd sieci też daje null. */
export async function checkForUpdate(current: string, fetchFn: typeof fetch = fetch, timeoutMs = 10_000): Promise<string | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetchFn(RELEASES_API, { headers: { Accept: 'application/vnd.github+json' }, signal: ctl.signal });
    if (!res.ok) return null;
    const list: unknown = await res.json();
    return Array.isArray(list) ? newerVersion(current, list as Release[]) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
