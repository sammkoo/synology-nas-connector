import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, stat, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { configSchema, NasFiles } from '../packages/core/src/index.js';
import { BridgeGuard, signBridgeRequest, ConfigurationStore, ShareCatalog, type BridgeRequest } from '../packages/management/src/index.js';
import { createHttpApp } from '../apps/server/src/http.js';
import { createMcpServer } from '../apps/server/src/mcp.js';
import { managementRouter } from '../apps/server/src/management.js';
import { bridgeAction, requireAdministrator } from '../apps/dsm-bridge/src/bridge.js';

const secret=Buffer.alloc(32,3);
const signed=(body=Buffer.alloc(0)): BridgeRequest=>({method:'POST',path:'/manage/roots',user:'admin',
  timestamp:String(Date.now()),nonce:randomBytes(32).toString('hex'),csrf:'',body});

test('signed management requests reject tampering, replay, old timestamps and remote callers',()=>{
  const guard=new BridgeGuard(secret); const r=signed(Buffer.from('{}'));
  const signature=signBridgeRequest(secret,r);
  assert.throws(()=>guard.verify({...r,body:Buffer.from('{"ids":[]}')},signature,'127.0.0.1'),/BRIDGE_AUTH_REQUIRED/);
  assert.throws(()=>guard.verify({...r,user:'other'},signature,'127.0.0.1'),/BRIDGE_AUTH_REQUIRED/);
  assert.throws(()=>guard.verify({...r,path:'/manage/preview'},signature,'127.0.0.1'),/BRIDGE_AUTH_REQUIRED/);
  assert.throws(()=>guard.verify(r,signature,'192.0.2.10'),/LOCAL_BRIDGE_REQUIRED/);
  guard.verify(r,signature,'127.0.0.1');
  assert.throws(()=>guard.verify(r,signature,'127.0.0.1'),/BRIDGE_REPLAY_DENIED/);
  const old={...signed(),timestamp:String(Date.now()-20000)};
  assert.throws(()=>guard.verify(old,signBridgeRequest(secret,old),'127.0.0.1'),/BRIDGE_AUTH_REQUIRED/);
});
test('setup CSRF token is bound to user, expires and is invalidated on new bootstrap',()=>{
  let now=Date.now(); const guard=new BridgeGuard(secret,()=>now);
  const token=guard.issueCsrf('admin'); guard.checkCsrf('admin',token);
  assert.throws(()=>guard.checkCsrf('other',token),/SESSION_EXPIRED/);
  guard.issueCsrf('admin'); assert.throws(()=>guard.checkCsrf('admin',token),/SESSION_EXPIRED/);
  const latest=guard.issueCsrf('admin'); now+=15*60_000;
  assert.throws(()=>guard.checkCsrf('admin',latest),/SESSION_EXPIRED/);
});
test('DSM bridge requires exact admin group, fixed actions and same HTTPS origin for mutations',()=>{
  assert.equal(requireAdministrator('samuel','users administrators'),'samuel');
  assert.throws(()=>requireAdministrator('person','users fake-administrators'),/DSM_ADMIN_REQUIRED/);
  assert.throws(()=>requireAdministrator('-root','administrators'),/DSM_ADMIN_REQUIRED/);
  const env={REQUEST_METHOD:'POST',QUERY_STRING:'action=roots',HTTP_HOST:'nas.example',HTTP_ORIGIN:'https://nas.example',CONTENT_TYPE:'application/json'};
  assert.equal(bridgeAction(env).endpoint,'/manage/roots');
  assert.throws(()=>bridgeAction({...env,HTTP_ORIGIN:'https://evil.example'}),/ORIGIN_REQUIRED/);
  assert.throws(()=>bridgeAction({...env,QUERY_STRING:'action=roots&path=/etc'}),/UNKNOWN_ACTION/);
  assert.throws(()=>bridgeAction({...env,REQUEST_METHOD:'GET'}),/METHOD_NOT_ALLOWED/);
});

test('management HTTP saves aliases only, rejects forged requests and applies revocation to an existing MCP session',async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),'nas-manage-'));
  let listener: ReturnType<ReturnType<typeof createHttpApp>['listen']> | undefined;
  const client=new Client({name:'management-test',version:'1'});
  let mcp: ReturnType<typeof createMcpServer> | undefined;
  try {
    const volume=path.join(directory,'volume1'); await mkdir(volume);
    const docs=path.join(volume,'Documents'); await mkdir(docs);
    await writeFile(path.join(docs,'note.txt'),'private NAS text');
    await mkdir(path.join(volume,'@private')); await symlink(docs,path.join(volume,'linked'));
    const filename=path.join(directory,'config.json');
    const config=configSchema.parse({roots:[],http:{tokenFile:path.join(directory,'token')}});
    await writeFile(filename,JSON.stringify(config),{mode:0o600});
    const store=await ConfigurationStore.create(filename,config,new ShareCatalog([volume]));
    const guard=new BridgeGuard(secret);
    const app=createHttpApp(config,()=>store.getFiles(),{mode:'local-token',challenge:'Bearer',authenticate:async()=>null},'missing-ui',managementRouter(store,guard));
    listener=app.listen(0,'127.0.0.1'); await new Promise<void>(r=>listener!.once('listening',r));
    const base=`http://127.0.0.1:${(listener.address() as {port:number}).port}`;
    async function call(action:string,body?:unknown,csrf='',sign=true) {
      const bytes=body===undefined?Buffer.alloc(0):Buffer.from(JSON.stringify(body));
      const r={...signed(bytes),method:body===undefined?'GET':'POST',path:`/manage/${action}`,csrf};
      return fetch(base+r.path,{method:r.method,headers:{'Content-Type':'application/json','x-nas-user':r.user,
        'x-nas-timestamp':r.timestamp,'x-nas-nonce':r.nonce,'x-nas-csrf':csrf,
        'x-nas-signature':sign?signBridgeRequest(secret,r):'0'.repeat(64)},...(body===undefined?{}:{body:bytes.toString()})});
    }
    assert.equal((await call('bootstrap',undefined,'',false)).status,401);
    // An MCP token is never a management credential.
    assert.equal((await fetch(base+'/manage/bootstrap',{headers:{Authorization:'Bearer '+'a'.repeat(43)}})).status,401);
    const bootstrap=await (await call('bootstrap')).json() as {csrf:string;revision:string;shares:{id:string}[]};
    assert.equal(bootstrap.shares.length,1); assert.ok(!JSON.stringify(bootstrap).includes(directory));
    const id=bootstrap.shares[0]!.id;
    assert.equal((await call('roots',{ids:[id],revision:bootstrap.revision})).status,419);
    assert.equal((await call('roots',{ids:['/etc'],revision:bootstrap.revision},bootstrap.csrf)).status,400);
    const selected=await call('roots',{ids:[id],revision:bootstrap.revision},bootstrap.csrf);
    assert.equal(selected.status,200);
    const saved=await selected.json() as {revision:string};
    assert.equal((await stat(filename)).mode&0o777,0o600);
    assert.equal((JSON.parse(await readFile(filename,'utf8'))).roots[0].path,await realpath(docs));
    assert.equal((await call('roots',{ids:[],revision:bootstrap.revision},bootstrap.csrf)).status,409);
    const [ct,st]=InMemoryTransport.createLinkedPair();
    mcp=createMcpServer(()=>store.getFiles(),{subject:'local-owner',scopes:['nas:read']});
    await mcp.connect(st); await client.connect(ct);
    assert.match(JSON.stringify(await client.callTool({name:'read_text',arguments:{rootId:id,path:'note.txt'}})),/private NAS text/);
    assert.equal((await call('roots',{ids:[],revision:saved.revision},bootstrap.csrf)).status,200);
    assert.equal((await client.callTool({name:'read_text',arguments:{rootId:id,path:'note.txt'}})).isError,true);
    assert.equal((await readFile(path.join(docs,'note.txt'),'utf8')),'private NAS text');
  } finally {
    await client.close(); await mcp?.close();
    if(listener) {listener.closeAllConnections();await new Promise<void>(r=>listener!.close(()=>r()));}
    await rm(directory,{recursive:true,force:true});
  }
});
test('an in-flight read does not return content after policy revocation',async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),'nas-revoke-'));
  const config=configSchema.parse({roots:[{id:'docs',path:directory,label:'Docs'}],http:{tokenFile:'token'}});
  let files=await NasFiles.create(config);
  let finish!:()=>void; let started!:()=>void;
  const ready=new Promise<void>(r=>started=r); const pending=new Promise<void>(r=>finish=r);
  files.readText=async()=>{started();await pending;return {rootId:'docs',path:'note.txt',text:'must not escape',startLine:1,totalLines:1,truncated:false,trust:'untrusted'};};
  const mcp=createMcpServer(()=>files,{subject:'owner',scopes:['nas:read']});
  const client=new Client({name:'revocation-test',version:'1'});
  const [ct,st]=InMemoryTransport.createLinkedPair();
  try {
    await mcp.connect(st); await client.connect(ct);
    const read=client.callTool({name:'read_text',arguments:{rootId:'docs',path:'note.txt'}});
    await ready; files=await NasFiles.create({...config,roots:[]}); finish();
    const result=await read; assert.equal(result.isError,true);
    assert.match(JSON.stringify(result),/CONFIGURATION_CHANGED/);
    assert.ok(!JSON.stringify(result).includes('must not escape'));
  } finally {await client.close();await mcp.close();await rm(directory,{recursive:true,force:true});}
});
test('package management migration preserves selected folders and MCP token on repeated upgrade',async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),'nas-upgrade-'));
  try {
    const filename=path.join(directory,'config.json');
    const before={roots:[{id:'docs',path:'/volume1/Documents',label:'Documents'}],http:{host:'127.0.0.1',tokenFile:'token'}};
    await writeFile(filename,JSON.stringify(before),{mode:0o600});
    await writeFile(path.join(directory,'token'),'existing-token',{mode:0o600});
    execFileSync(process.execPath,['scripts/enable-management.mjs',directory]);
    const after=JSON.parse(await readFile(filename,'utf8'));
    assert.deepEqual(after.roots,before.roots);assert.deepEqual(after.http,before.http);
    const key=await readFile(path.join(directory,'management-secret'),'utf8');
    assert.match(key,/^[a-f0-9]{64}\n$/);
    execFileSync(process.execPath,['scripts/enable-management.mjs',directory]);
    assert.equal(await readFile(path.join(directory,'management-secret'),'utf8'),key);
    assert.equal(await readFile(path.join(directory,'token'),'utf8'),'existing-token');
  } finally {await rm(directory,{recursive:true,force:true});}
});
