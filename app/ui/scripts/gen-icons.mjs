// Generuje src/lib/icons.generated.ts z design/icons/*.svg (tylko elementy graficzne, bez metadanych).
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '../../../design/icons');
const out = join(here, '../src/lib/icons.generated.ts');

const icons = {};
for (const file of readdirSync(dir).filter((f) => f.endsWith('.svg')).sort()) {
  const svg = readFileSync(join(dir, file), 'utf8');
  const m = svg.match(/<\/metadata>([\s\S]*?)<\/svg>/) ?? svg.match(/<svg[^>]*>([\s\S]*?)<\/svg>/);
  icons[file.replace(/\.svg$/, '')] = (m?.[1] ?? '').trim();
}
const body = `// Plik wygenerowany przez scripts/gen-icons.mjs z design/icons/. Nie edytuj ręcznie.\nexport const iconPaths: Record<string, string> = ${JSON.stringify(icons, null, 2)};\n`;
writeFileSync(out, body);
console.log(`Zapisano ${Object.keys(icons).length} ikon do ${out}`);
