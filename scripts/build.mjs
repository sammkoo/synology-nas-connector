import { build } from 'esbuild';
import { mkdir, cp, readFile, writeFile, readdir } from 'node:fs/promises';
import path from 'node:path';
await mkdir('dist', {recursive: true});
const result = await build({entryPoints: ['apps/server/src/cli.ts'], outfile: 'dist/server.cjs', bundle: true,
  platform: 'node', target: 'node22', format: 'cjs', sourcemap: false, legalComments: 'eof', metafile: true});
const used = new Set();
for (const input of Object.keys(result.metafile.inputs)) {
  const split = input.lastIndexOf('node_modules/');
  if (split < 0) continue;
  const pieces = input.slice(split + 'node_modules/'.length).split('/');
  const name = pieces[0].startsWith('@') ? pieces.slice(0, 2).join('/') : pieces[0];
  used.add(path.join(input.slice(0, split), 'node_modules', name));
}
const notices = [];
for (const dir of [...used].sort()) {
  const manifest = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8'));
  const licenses = (await readdir(dir)).filter(f => /^(license|copying)(\.|$)/i.test(f)).sort();
  if (!licenses.length) throw new Error(`Missing bundled dependency license: ${manifest.name}`);
  notices.push(`${manifest.name} ${manifest.version} (${manifest.license})\n` +
    (await Promise.all(licenses.map(f => readFile(path.join(dir, f), 'utf8')))).join('\n'));
}
await writeFile('dist/THIRD_PARTY_NOTICES.txt', notices.join('\n\n----------------------------------------\n\n'));
await cp('apps/dsm-ui/public', 'dist/ui', {recursive: true});
console.log('Built portable Node.js server and DSM UI');
