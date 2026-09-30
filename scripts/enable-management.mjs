// Package lifecycle migration only. Never reads or changes NAS document data.
import { lstat, readFile, writeFile, rename, unlink } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import path from 'node:path';
const directory = path.resolve(process.argv[2]);
const filename = path.join(directory,'config.json');
const stat = await lstat(filename);
if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || stat.mode & 0o077)
  throw new Error('Private package-owned configuration required');
const config = JSON.parse(await readFile(filename,'utf8'));
if (!config.http || config.http.host !== '127.0.0.1') throw new Error('DSM management requires loopback binding');
if (config.management) {
  if (config.management.secretFile !== 'management-secret') throw new Error('Unexpected management configuration');
  process.exit(0);
}
const secretPath = path.join(directory,'management-secret');
// Recover a migration interrupted after secret creation, without rotating its key.
try {await writeFile(secretPath,randomBytes(32).toString('hex')+'\n',{flag:'wx',mode:0o600});}
catch (e) {if(e.code !== 'EEXIST') throw e;}
const secretStat = await lstat(secretPath);
if (!secretStat.isFile() || secretStat.isSymbolicLink() || secretStat.uid !== process.getuid() || secretStat.mode & 0o077 ||
    !/^[a-f0-9]{64}\n$/.test(await readFile(secretPath,'utf8'))) throw new Error('Invalid private management secret');
config.management = {secretFile:'management-secret'};
const temporary = path.join(directory,`.management-${randomUUID()}.tmp`);
try {
  await writeFile(temporary,JSON.stringify(config,null,2)+'\n',{flag:'wx',mode:0o600});
  await rename(temporary,filename);
} finally {await unlink(temporary).catch(()=>{});}
