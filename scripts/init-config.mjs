import { mkdir, writeFile, lstat } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
const dest = path.resolve(process.argv[2] ?? '.local');
for (const name of ['token','config.json']) {
  const exists = await lstat(path.join(dest,name)).then(()=>true,error=>{if(error.code==='ENOENT') return false; throw error;});
  if (exists) throw new Error('Existing configuration detected; refusing to overwrite or repair implicitly');
}
await mkdir(dest, {recursive: true, mode: 0o700});
const token = path.join(dest, 'token');
// wx never overwrites an existing installation's token/config.
await writeFile(token, randomBytes(32).toString('base64url') + '\n', {mode: 0o600, flag: 'wx'});
await writeFile(path.join(dest, 'config.json'), JSON.stringify({roots: [], http: {
  tokenFile: 'token', host: '127.0.0.1', port: 8787, allowedHosts: ['127.0.0.1', 'localhost'],
  allowedOrigins: ['http://127.0.0.1:8787', 'http://localhost:8787']
}}, null, 2) + '\n', {mode: 0o600, flag: 'wx'});
console.log(`Created private config at ${dest}; add only selected absolute folder paths to roots.`);
