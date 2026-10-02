import { build } from 'esbuild';
import { mkdir, cp, readFile, writeFile, readdir } from 'node:fs/promises';
import path from 'node:path';
await mkdir('dist', {recursive: true});
await build({entryPoints:['apps/dsm-bridge/src/cgi.ts'],outfile:'dist/dsm-bridge.cjs',bundle:true,
  platform:'node',target:'node22',format:'cjs',legalComments:'eof'});
const result = await build({entryPoints: ['apps/server/src/cli.ts'], outfile: 'dist/server.cjs', bundle: true,
  platform: 'node', target: 'node22', format: 'cjs', sourcemap: false, legalComments: 'eof', metafile: true,external:['bufferutil','utf-8-validate']});
if(Object.keys(result.metafile.inputs).some(p=>p.startsWith('packages/gateway/'))||result.metafile.outputs['dist/server.cjs'].imports.some(p=>p.path==='node:sqlite'))
  throw new Error('Gateway-only SQLite must never enter the NAS bundle');
const gateway = await build({entryPoints:['apps/gateway/src/cli.ts'],outfile:'dist/gateway.cjs',bundle:true,
  platform:'node',target:'node22',format:'cjs',legalComments:'eof',metafile:true,external:['bufferutil','utf-8-validate']});
const office = await build({entryPoints:['apps/office-dev/src/cli.ts'],outfile:'dist/office-dev.cjs',bundle:true,
  platform:'node',target:'node22',format:'cjs',legalComments:'eof',metafile:true});
const officeAcceptance = await build({entryPoints:['scripts/office-live-acceptance.ts'],outfile:'dist/office-live-acceptance.cjs',bundle:true,
  platform:'node',target:'node22',format:'cjs',legalComments:'eof',metafile:true});
if(Object.keys(result.metafile.inputs).some(p=>p.startsWith('packages/office/')))
  throw new Error('Experimental Office access must not enter the NAS bundle');
async function writeNotices(metafile,filename) {
const used = new Set();
for (const input of Object.keys(metafile.inputs)) {
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
await writeFile(filename, notices.join('\n\n----------------------------------------\n\n'));
}
await writeNotices(result.metafile,'dist/THIRD_PARTY_NOTICES.txt');
await writeNotices(gateway.metafile,'dist/GATEWAY_THIRD_PARTY_NOTICES.txt');
await writeNotices(office.metafile,'dist/OFFICE_THIRD_PARTY_NOTICES.txt');
await writeNotices(officeAcceptance.metafile,'dist/OFFICE_ACCEPTANCE_THIRD_PARTY_NOTICES.txt');
await cp('apps/dsm-ui/public', 'dist/ui', {recursive: true});
console.log('Built portable NAS server, gateway service and DSM UI');
