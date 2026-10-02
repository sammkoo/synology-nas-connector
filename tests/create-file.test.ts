import {test,beforeEach,afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,readdir,rm,symlink,lstat} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {NasFiles,configSchema,NasError,operationSchema} from '../packages/core/src/index.js';

let directory:string,files:NasFiles;
beforeEach(async()=>{
  directory=await mkdtemp(path.join(tmpdir(),'nas-create-'));
  await mkdir(path.join(directory,'folder'));
  files=await NasFiles.create(configSchema.parse({roots:[{id:'docs',label:'Docs',path:directory,allowCreate:true}],http:{tokenFile:'unused'}}));
});
afterEach(async()=>{await rm(directory,{recursive:true,force:true});});
const linux={skip:process.platform!=='linux'};
test('old configuration remains read-only and byte limits reject multibyte payloads',async()=>{
  const old=await NasFiles.create(configSchema.parse({roots:[{id:'docs',label:'Docs',path:directory}],http:{tokenFile:'unused'}}));
  assert.deepEqual(old.listRoots(),[{id:'docs',label:'Docs'}]);
  await assert.rejects(old.createFile('docs','new.txt','test'),/CREATE_DENIED/);
  assert.equal(operationSchema.safeParse({name:'create_file',args:{rootId:'docs',path:'new.txt',content:'é'.repeat(8193)}}).success,false);
  assert.equal(operationSchema.safeParse({name:'create_file',args:{rootId:'docs',path:'new.txt',content:'ok',overwrite:true}}).success,false);
});
test('non-Linux writes fail closed instead of using a racy path fallback',{skip:process.platform==='linux'},async()=>{
  await assert.rejects(files.createFile('docs','new.txt','Hello'),/CREATE_REQUIRES_LINUX/);
  assert.deepEqual(await readdir(directory),['folder']);
});
test('create publishes a complete UTF-8 file with private mode and a content receipt',linux,async()=>{
  const content='Nový súbor\nUTF-8 ✓',result=await files.createFile('docs','folder/new.md',content);
  assert.equal(result.created,true);assert.equal(result.size,Buffer.byteLength(content));assert.match(result.sha256,/^[a-f0-9]{64}$/);
  assert.equal(await readFile(path.join(directory,'folder/new.md'),'utf8'),content);
  assert.equal((await lstat(path.join(directory,'folder/new.md'))).mode&0o777,0o600);
  assert.deepEqual(await readdir(path.join(directory,'folder')),['new.md']);
});
test('exclusive publication never overwrites existing files, directories or symlinks',linux,async()=>{
  await writeFile(path.join(directory,'existing.txt'),'original');
  await mkdir(path.join(directory,'directory.txt'));
  await symlink(path.join(directory,'existing.txt'),path.join(directory,'link.txt'));
  for(const name of ['existing.txt','directory.txt','link.txt'])await assert.rejects(files.createFile('docs',name,'replacement'),/FILE_EXISTS/);
  assert.equal(await readFile(path.join(directory,'existing.txt'),'utf8'),'original');
  assert.equal((await lstat(path.join(directory,'link.txt'))).isSymbolicLink(),true);
  assert.ok(!(await readdir(directory)).some(n=>n.startsWith('.nas-create-')));
});
test('parallel attempts for the same path produce exactly one complete file',linux,async()=>{
  const results=await Promise.allSettled(Array.from({length:12},(_,i)=>files.createFile('docs','new.txt',String(i))));
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  for(const r of results)if(r.status==='rejected')assert.match(r.reason.code,/FILE_EXISTS/);
  const content=await readFile(path.join(directory,'new.txt'),'utf8');assert.match(content,/^\d{1,2}$/);
  assert.ok(!(await readdir(directory)).some(n=>n.startsWith('.nas-create-')));
});
test('traversal, hidden names, symlink parents, unsupported formats and missing parents cannot be created',linux,async()=>{
  const outside=await mkdtemp(path.join(tmpdir(),'nas-create-outside-'));
  try {
    await symlink(outside,path.join(directory,'escape'));
    for(const name of ['../escape.txt','/tmp/escape.txt','folder//new.txt','folder/./new.txt','.hidden.txt','token','secret.pem','report.pdf','escape/new.txt','missing/new.txt'])await assert.rejects(files.createFile('docs',name,'payload'));
    assert.deepEqual(await readdir(outside),[]);
    await assert.rejects(files.createFile('other','new.txt','payload'),/CREATE_DENIED/);
  }finally{await rm(outside,{recursive:true,force:true});}
});
test('revocation or cancellation before publication leaves no target or temporary file',linux,async()=>{
  await assert.rejects(files.createFile('docs','new.txt','secret',undefined,async()=>{throw new NasError('CONFIGURATION_CHANGED');}),/CONFIGURATION_CHANGED/);
  const controller=new AbortController();
  await assert.rejects(files.createFile('docs','new.txt','secret',controller.signal,async()=>{controller.abort();}),/CANCELLED/);
  assert.deepEqual(await readdir(directory),['folder']);
});
test('content checks reject invalid UTF-16, controls and oversized UTF-8 without staging',async()=>{
  for(const [content,code] of [['\ud800','INVALID_UTF8'],['\0','BINARY_CONTENT'],['é'.repeat(8193),'FILE_TOO_LARGE']])await assert.rejects(files.createFile('docs','new.txt',content!),new RegExp(code!));
  assert.deepEqual(await readdir(directory),['folder']);
});
